using System.Net;
using System.Net.Sockets;
using ITBees.Mikrotik.Api;
using ITBees.Mikrotik.Configuration;
using ITBees.Mikrotik.WireGuard;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ITBees.Mikrotik.Provisioning;

/// <summary>
/// Applies a <see cref="MikrotikConfigurationPackage"/> to a router over the API. Steps run in a fixed order chosen
/// so that the session survives: firewall accept rules go in before drop rules, the password is verified on a
/// second session before it is relied on, and the LAN address (which a computer on the LAN uses to reach the
/// router) changes last, in a single command.
/// </summary>
public sealed class MikrotikProvisioner
{
    private readonly ILogger _logger;

    public MikrotikProvisioner(ILogger<MikrotikProvisioner>? logger = null)
    {
        _logger = (ILogger?)logger ?? NullLogger.Instance;
    }

    /// <exception cref="MikrotikConfigurationException">The package is invalid; nothing was sent.</exception>
    public async Task<MikrotikProvisioningResult> ApplyAsync(
        IMikrotikClient client,
        MikrotikConfigurationPackage package,
        MikrotikProvisioningOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(package);
        options ??= new MikrotikProvisioningOptions();

        var validation = package.Validate();
        validation.ThrowIfInvalid();
        var resolved = MikrotikConfigurationValidator.Resolve(package);

        var result = new MikrotikProvisioningResult { DryRun = options.DryRun };
        result.Warnings.AddRange(validation.Warnings);
        var run = new ProvisioningRun(client, package, resolved, options, result, _logger);
        await run.ExecuteAsync(cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Provisioning of {Host} finished: {Result}", client.Host, result);
        return result;
    }
}

internal sealed class ProvisioningRun
{
    private const string WanList = "WAN";
    private const string LanList = "LAN";
    private const string VpnList = "VPN";
    private const string LanAddressComment = "itbees:lan";

    private readonly IMikrotikClient _client;
    private readonly MikrotikConfigurationPackage _package;
    private readonly ResolvedPackage _resolved;
    private readonly MikrotikProvisioningOptions _options;
    private readonly MikrotikProvisioningResult _result;
    private readonly ILogger _logger;
    private readonly RouterOsStateWriter _writer;

    private HashSet<string> _interfaces = new(StringComparer.Ordinal);
    private bool _ltePresent;
    private bool _schedulerAllowed = true;
    private string? _deviceMode;
    private string? _managementInterface;
    private IPAddress? _sessionAddress;
    private bool _sessionViaLanIpv4;
    private string? _wanGateway;

    public ProvisioningRun(IMikrotikClient client, MikrotikConfigurationPackage package, ResolvedPackage resolved, MikrotikProvisioningOptions options, MikrotikProvisioningResult result, ILogger logger)
    {
        _client = client;
        _package = package;
        _resolved = resolved;
        _options = options;
        _result = result;
        _logger = logger;
        _writer = new RouterOsStateWriter(client.Api, options.DryRun, logger);
    }

    private string Wan => _package.Wan.Interface;

    private string Bridge => _package.Lan.BridgeName;

    private string Lte => _package.Lte.Interface;

    /// <summary>Parking devices share the site network on the WAN port (see <see cref="LanMode.SharedSiteNetwork"/>).</summary>
    private bool Shared => _package.Lan.Mode == LanMode.SharedSiteNetwork;

    public async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        var steps = new (string Name, Func<CancellationToken, Task<StepOutcome>> Run)[]
        {
            ("Preflight", PreflightAsync),
            ("System", SystemAsync),
            ("LAN bridge", BridgeAsync),
            ("Interface lists", InterfaceListsAsync),
            ("DNS", DnsAsync),
            ("LTE backup", LteAsync),
            // Failover routes go in before the WAN DHCP client stops adding its own default route,
            // so the router never loses its default route (matters when re-applying over the VPN).
            ("Failover", FailoverAsync),
            ("WAN (DHCP client)", WanAsync),
            ("NAT", NatAsync),
            ("Firewall", FirewallAsync),
            ("Services", ServicesAsync),
            ("VPN", VpnAsync),
            ("LAN DHCP", LanDhcpAsync),
            ("Password", PasswordAsync),
            ("LAN address", LanAddressAsync),
        };

        var failed = false;
        foreach (var (name, run) in steps)
        {
            if (failed)
            {
                _result.Steps.Add(new ProvisioningStepResult(name, ProvisioningStepStatus.NotRun, 0, null));
                continue;
            }
            _writer.Step = name;
            var before = _writer.Changes.Count;
            try
            {
                var outcome = await run(cancellationToken).ConfigureAwait(false);
                var changes = _writer.Changes.Count - before;
                var status = outcome.Skipped ? ProvisioningStepStatus.Skipped : changes > 0 ? ProvisioningStepStatus.Changed : ProvisioningStepStatus.Unchanged;
                _result.Steps.Add(new ProvisioningStepResult(name, status, changes, outcome.Message));
            }
            catch (MikrotikException e)
            {
                failed = true;
                _result.Error = $"{name}: {e.Message}";
                _result.Steps.Add(new ProvisioningStepResult(name, ProvisioningStepStatus.Failed, _writer.Changes.Count - before, e.Message));
                _logger.LogError("Provisioning step {Step} failed: {Message}", name, e.Message);
            }
        }

        _result.Changes.AddRange(_writer.Changes);
        _result.Success = !failed;
    }

    // ---------------------------------------------------------------- preflight

    private async Task<StepOutcome> PreflightAsync(CancellationToken ct)
    {
        var device = await _client.RefreshDeviceInfoAsync(ct).ConfigureAwait(false);
        _result.Device = device;
        if (device.Version.Major < 7)
            throw Fail($"RouterOS 7 is required (WireGuard, v7 menus); the router runs {device.Version}. Upgrade it first (System > Packages > Check For Updates).");
        if (device.Model != null && !device.Model.Contains("RB960", StringComparison.OrdinalIgnoreCase))
            Warn($"The package is designed for RB960PGS (hEX PoE); this router is {device.Model}. Continuing because the interfaces are checked below.");
        _schedulerAllowed = await IsSchedulerAllowedAsync(ct).ConfigureAwait(false);

        var interfaces = await _writer.PrintAsync("/interface", ct).ConfigureAwait(false);
        _interfaces = interfaces.Select(i => i.Get("name")).OfType<string>().ToHashSet(StringComparer.Ordinal);
        if (!_interfaces.Contains(Wan))
            throw Fail($"WAN interface {Wan} does not exist on this router.");
        var missing = _package.Lan.Ports.Where(p => !_interfaces.Contains(p)).ToList();
        if (missing.Count > 0)
            throw Fail($"LAN port(s) {string.Join(", ", missing)} do not exist on this router.");

        if (_package.Lte.Enabled)
        {
            _ltePresent = _interfaces.Contains(Lte);
            if (!_ltePresent)
            {
                if (_package.Lte.Required)
                    throw Fail($"LTE modem not detected ({Lte} missing). Plug the Huawei E3372 into the USB port and wait ~30 s.");
                Warn($"LTE modem not detected ({Lte} missing): LTE backup is skipped. Plug the Huawei E3372 into USB and apply the package again.");
            }
        }
        _result.LteDetected = _ltePresent;

        _sessionAddress = ParseSessionAddress();
        _managementInterface = await FindInterfaceOfAddressAsync(_sessionAddress, ct).ConfigureAwait(false);
        if (_managementInterface == null)
        {
            Warn($"Could not tell which router interface this session uses ({_sessionAddress?.ToString() ?? "unknown"}); make sure it is a LAN port or the VPN.");
        }
        else if (((_managementInterface == Wan && !Shared) || (_package.Lte.Enabled && _managementInterface == Lte)) && !_options.AllowManagementOverWan)
        {
            // In SharedSiteNetwork mode the parking devices (and the column applying the package) live on the WAN
            // port's network, and the managed firewall keeps it open for the parking subnet.
            throw Fail($"This session reaches the router through {_managementInterface} (WAN/LTE), which the managed firewall closes. Connect the computer to a LAN port (ether2-ether5) or use the VPN.");
        }
        // In SharedSiteNetwork mode the bridge loses every IPv4 address, so a session on a LAN port always ends.
        _sessionViaLanIpv4 = _sessionAddress?.AddressFamily == AddressFamily.InterNetwork
                             && _managementInterface != null
                             && (_managementInterface == Bridge || _package.Lan.Ports.Contains(_managementInterface))
                             && (Shared || !_sessionAddress.Equals(_resolved.Lan.Address));

        var lease = (await _writer.PrintAsync("/ip/dhcp-client", ct, ("interface", Wan)).ConfigureAwait(false)).FirstOrDefault();
        CheckWanOverlap(lease);
        if (lease?.Get("status") == "bound")
            _wanGateway = lease.Get("gateway");

        return new StepOutcome($"RouterOS {device.Version}, {device.Model ?? device.BoardName}, session via {_managementInterface ?? "?"}");
    }

    /// <summary>
    /// Since RouterOS 7.17 home routers leave the factory in device-mode "home", which blocks /system/scheduler.
    /// Changing the mode needs a button press on the router, so the VPN watchdog runs from netwatch instead.
    /// Versions without device-mode have no such menu.
    /// </summary>
    private async Task<bool> IsSchedulerAllowedAsync(CancellationToken ct)
    {
        try
        {
            var mode = await _writer.GetSingletonAsync("/system/device-mode", ct).ConfigureAwait(false);
            _deviceMode = mode?.Get("mode");
            return mode?.GetBool("scheduler") ?? !string.Equals(_deviceMode, "home", StringComparison.OrdinalIgnoreCase);
        }
        catch (MikrotikCommandException e)
        {
            _logger.LogDebug("No device-mode menu: {Message}", e.Message);
            return true;
        }
    }

    private IPAddress? ParseSessionAddress()
    {
        if (_options.SessionRouterAddress != null)
            return IPAddress.TryParse(_options.SessionRouterAddress, out var configured) ? configured : null;
        var address = _client.Api.RemoteEndPoint?.Address;
        if (address == null)
            return null;
        if (address.IsIPv4MappedToIPv6)
            return address.MapToIPv4();
        return address;
    }

    private async Task<string?> FindInterfaceOfAddressAsync(IPAddress? address, CancellationToken ct)
    {
        if (address == null)
            return null;
        try
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                foreach (var row in await _writer.PrintAsync("/ip/address", ct).ConfigureAwait(false))
                    if (Ipv4Prefix.TryParse(row.Get("address"), out var prefix) && prefix.Address.Equals(address))
                        return row.Get("interface");
                return null;
            }

            var wanted = address.GetAddressBytes();
            foreach (var row in await _writer.PrintAsync("/ipv6/address", ct).ConfigureAwait(false))
            {
                var text = row.Get("address")?.Split('/')[0];
                if (text != null && IPAddress.TryParse(text, out var ip) && ip.GetAddressBytes().AsSpan().SequenceEqual(wanted))
                    return row.Get("interface");
            }
        }
        catch (MikrotikCommandException e)
        {
            _logger.LogDebug("Cannot list addresses: {Message}", e.Message);
        }
        return null;
    }

    private void CheckWanOverlap(RouterOsRecord? lease)
    {
        if (lease?.Get("status") != "bound" || !Ipv4Prefix.TryParse(lease.Get("address"), out var wanNetwork))
            return;
        if (wanNetwork.Overlaps(_resolved.Lan))
            throw Fail($"The site network on {Wan} ({wanNetwork.NetworkCidr}) overlaps the parking LAN {_resolved.LanCidr}. Choose another Lan.Address.");
        foreach (var vpn in _resolved.VpnNetworks)
            if (vpn.Overlaps(wanNetwork))
                Warn($"The site network on {Wan} ({wanNetwork.NetworkCidr}) overlaps the VPN network {vpn.NetworkCidr}; hosts in that range will not be reachable over the VPN.");
    }

    // ---------------------------------------------------------------- system

    private async Task<StepOutcome> SystemAsync(CancellationToken ct)
    {
        if (_package.Identity != null)
            await _writer.EnsureSingletonAsync("/system/identity", new Props { { "name", _package.Identity } }, "router name", ct).ConfigureAwait(false);
        if (_package.Time.TimeZone != null)
        {
            await _writer.EnsureSingletonAsync(
                    "/system/clock",
                    new Props { { "time-zone-autodetect", "no" }, { "time-zone-name", _package.Time.TimeZone } },
                    "time zone",
                    ct)
                .ConfigureAwait(false);
        }
        if (_package.Time.NtpServers.Count > 0)
        {
            await _writer.EnsureSingletonAsync(
                    "/system/ntp/client",
                    new Props { { "enabled", "yes" }, { "servers", string.Join(",", _package.Time.NtpServers) } },
                    "NTP client",
                    ct)
                .ConfigureAwait(false);
        }
        return default;
    }

    // ---------------------------------------------------------------- LAN bridge and interface lists

    private async Task<StepOutcome> BridgeAsync(CancellationToken ct)
    {
        await _writer.EnsureAsync(
                "/interface/bridge",
                new[] { ("name", Bridge) },
                new Props { { "name", Bridge } },
                "LAN bridge",
                ct,
                addOnly: new Props { { "comment", "itbees:lan-bridge" } })
            .ConfigureAwait(false);

        var ports = (await _writer.PrintAsync("/interface/bridge/port", ct).ConfigureAwait(false)).Where(p => !p.IsDynamic).ToList();
        foreach (var port in _package.Lan.Ports)
        {
            var row = ports.FirstOrDefault(p => p.Get("interface") == port);
            if (row == null)
                await _writer.AddAsync("/interface/bridge/port", new Props { { "bridge", Bridge }, { "interface", port }, { "comment", "itbees:lan-port" } }, $"add {port} to {Bridge}", ct).ConfigureAwait(false);
            else if (row.Get("bridge") != Bridge)
                await _writer.SetAsync("/interface/bridge/port", row.Id!, new Props { { "bridge", Bridge } }, $"move {port} to {Bridge}", ct).ConfigureAwait(false);
        }

        foreach (var row in ports)
        {
            var name = row.Get("interface");
            var isUplink = name == Wan || (_package.Lte.Enabled && name == Lte);
            var isForeignPortOfOurBridge = row.Get("bridge") == Bridge && name != null && !_package.Lan.Ports.Contains(name);
            if (!isUplink && !isForeignPortOfOurBridge)
                continue;
            if (name == _managementInterface)
            {
                Warn($"{name} is not in Lan.Ports but this session uses it; left in {row.Get("bridge")}.");
                continue;
            }
            await _writer.RemoveAsync("/interface/bridge/port", row.Id!, $"remove {name} from {row.Get("bridge")}", ct).ConfigureAwait(false);
        }
        return default;
    }

    private async Task<StepOutcome> InterfaceListsAsync(CancellationToken ct)
    {
        var lists = new List<string> { WanList, LanList };
        if (_package.Vpn.Enabled)
            lists.Add(VpnList);
        foreach (var list in lists)
        {
            await _writer.EnsureAsync("/interface/list", new[] { ("name", list) }, new Props { { "name", list } }, $"interface list {list}", ct, addOnly: new Props { { "comment", "itbees:list" } })
                .ConfigureAwait(false);
        }

        var wanMembers = new List<string> { Wan };
        if (_ltePresent)
            wanMembers.Add(Lte);
        await EnsureListMembersAsync(WanList, wanMembers, exclusive: true, ct).ConfigureAwait(false);
        await EnsureListMembersAsync(LanList, new[] { Bridge }, exclusive: true, ct).ConfigureAwait(false);
        return default;
    }

    private async Task EnsureListMembersAsync(string list, IReadOnlyCollection<string> members, bool exclusive, CancellationToken ct)
    {
        var rows = (await _writer.PrintAsync("/interface/list/member", ct, ("list", list)).ConfigureAwait(false)).Where(r => !r.IsDynamic).ToList();
        foreach (var member in members)
        {
            if (!rows.Any(r => r.Get("interface") == member))
                await _writer.AddAsync("/interface/list/member", new Props { { "list", list }, { "interface", member }, { "comment", "itbees:list-member" } }, $"{member} in list {list}", ct).ConfigureAwait(false);
        }
        if (!exclusive)
            return;
        foreach (var row in rows.Where(r => !members.Contains(r.Get("interface") ?? string.Empty)))
            await _writer.RemoveAsync("/interface/list/member", row.Id!, $"{row.Get("interface")} out of list {list}", ct).ConfigureAwait(false);
    }

    // ---------------------------------------------------------------- WAN, DNS, LTE, failover

    private async Task<StepOutcome> WanAsync(CancellationToken ct)
    {
        if (_package.Wan.RemoveStaticAddresses)
        {
            foreach (var row in await _writer.PrintAsync("/ip/address", ct, ("interface", Wan)).ConfigureAwait(false))
            {
                // In SharedSiteNetwork mode the LAN address lives on the WAN port; the LAN address step owns it.
                if (row.IsDynamic || (Shared && row.Comment == LanAddressComment))
                    continue;
                if (_sessionAddress != null && Ipv4Prefix.TryParse(row.Get("address"), out var p) && p.Address.Equals(_sessionAddress))
                {
                    Warn($"Static address {row.Get("address")} on {Wan} is used by this session; left in place.");
                    continue;
                }
                await _writer.RemoveAsync("/ip/address", row.Id!, $"static address {row.Get("address")} from {Wan} (WAN uses DHCP)", ct).ConfigureAwait(false);
            }
        }

        var failover = _package.Failover.Enabled;
        var props = new Props
        {
            { "interface", Wan },
            { "disabled", "no" },
            { "add-default-route", failover ? "no" : "yes" },
            { "default-route-distance", failover ? null : "1" },
            { "use-peer-dns", RouterOsValues.Bool(_package.Wan.UsePeerDns) },
            { "use-peer-ntp", "no" },
            { "script", failover ? RouterOsScripts.WanLeaseScript() : string.Empty },
            { "comment", "itbees:wan" },
        };
        await _writer.EnsureAsync("/ip/dhcp-client", new[] { ("interface", Wan) }, props, $"DHCP client on {Wan}", ct).ConfigureAwait(false);

        if (_writer.DryRun)
            return new StepOutcome("lease not checked in a dry run");

        var lease = await WaitForLeaseAsync(Wan, TimeSpan.FromSeconds(Math.Max(0, _package.Wan.WaitForLeaseSeconds)), ct).ConfigureAwait(false);
        _result.WanStatus = lease?.Get("status");
        if (lease?.Get("status") == "bound")
        {
            _result.WanAddress = lease.Get("address");
            _result.WanGateway = _wanGateway = lease.Get("gateway");
            CheckWanOverlap(lease);
            if (failover && _wanGateway != null)
                await PointCheckRoutesAtAsync(_wanGateway, ct).ConfigureAwait(false);
            return new StepOutcome($"{Wan} got {_result.WanAddress} via {_result.WanGateway}");
        }
        Warn($"{Wan} has no DHCP lease yet (status: {_result.WanStatus ?? "unknown"}). Check the cable to the site network; the router uses LTE until a lease arrives.");
        return new StepOutcome($"no lease yet ({_result.WanStatus ?? "unknown"})");
    }

    /// <summary>
    /// The lease script only runs on lease changes; when the lease arrived (or changed) during this run the
    /// check routes are updated here.
    /// </summary>
    private async Task PointCheckRoutesAtAsync(string gateway, CancellationToken ct)
    {
        foreach (var route in await _writer.PrintAsync("/ip/route", ct).ConfigureAwait(false))
        {
            if (route.IsDynamic || !(route.Comment?.StartsWith(RouterOsScripts.WanCheckRoutePrefix, StringComparison.Ordinal) ?? false) || route.Get("gateway") == gateway)
                continue;
            await _writer.SetAsync("/ip/route", route.Id!, new Props { { "gateway", gateway } }, $"{route.Comment} via the new WAN gateway {gateway}", ct).ConfigureAwait(false);
        }
    }

    private async Task<RouterOsRecord?> WaitForLeaseAsync(string iface, TimeSpan wait, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + wait;
        while (true)
        {
            var lease = (await _writer.PrintAsync("/ip/dhcp-client", ct, ("interface", iface)).ConfigureAwait(false)).FirstOrDefault(r => !r.IsDynamic);
            if (lease?.Get("status") == "bound" || DateTime.UtcNow >= deadline)
                return lease;
            await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
        }
    }

    private async Task<StepOutcome> DnsAsync(CancellationToken ct)
    {
        await _writer.EnsureSingletonAsync(
                "/ip/dns",
                new Props { { "servers", string.Join(",", _package.Dns.Servers) }, { "allow-remote-requests", RouterOsValues.Bool(_package.Dns.AllowRemoteRequests) } },
                "DNS servers",
                ct)
            .ConfigureAwait(false);
        return default;
    }

    private async Task<StepOutcome> LteAsync(CancellationToken ct)
    {
        var lte = _package.Lte;
        if (!lte.Enabled)
        {
            await _writer.RemoveStaleAsync("/ip/dhcp-client", "itbees:lte", Array.Empty<string>(), "LTE DHCP client (LTE disabled)", ct).ConfigureAwait(false);
            return new StepOutcome("LTE disabled in the package", Skipped: true);
        }
        if (!_ltePresent)
            return new StepOutcome($"modem not detected ({Lte} missing)", Skipped: true);

        var distance = lte.RouteDistance.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (lte.Mode == LteMode.HiLink)
        {
            // RouterOS 7 adds its own dynamic DHCP client for many HiLink (ECM) sticks and refuses a second
            // client on the same interface. That client cannot be edited; it takes its settings from the
            // APN profile of the LTE interface.
            var clients = await _writer.PrintAsync("/ip/dhcp-client", ct, ("interface", Lte)).ConfigureAwait(false);
            if (!clients.Any(r => !r.IsDynamic) && clients.FirstOrDefault(r => r.IsDynamic) != null)
                return await LteRouterOsDhcpClientAsync(distance, ct).ConfigureAwait(false);

            await _writer.EnsureAsync(
                    "/ip/dhcp-client",
                    new[] { ("interface", Lte) },
                    new Props
                    {
                        { "interface", Lte },
                        { "disabled", "no" },
                        { "add-default-route", "yes" },
                        { "default-route-distance", distance },
                        { "use-peer-dns", "no" },
                        { "use-peer-ntp", "no" },
                        { "comment", "itbees:lte" },
                    },
                    $"DHCP client on {Lte} (HiLink, backup default route distance {distance})",
                    ct)
                .ConfigureAwait(false);

            var lease = (await _writer.PrintAsync("/ip/dhcp-client", ct, ("interface", Lte)).ConfigureAwait(false)).FirstOrDefault();
            return new StepOutcome(lease?.Get("status") == "bound" ? $"{Lte} got {lease.Get("address")}" : $"{Lte} lease: {lease?.Get("status") ?? "pending"}");
        }

        await _writer.EnsureAsync(
                "/interface/lte/apn",
                new[] { ("name", "itbees") },
                new Props
                {
                    { "name", "itbees" },
                    { "apn", lte.Apn },
                    { "add-default-route", "yes" },
                    { "default-route-distance", distance },
                    { "use-peer-dns", "no" },
                },
                "LTE APN profile",
                ct)
            .ConfigureAwait(false);
        var modem = (await _writer.PrintAsync("/interface/lte", ct, ("name", Lte)).ConfigureAwait(false)).FirstOrDefault()
                    ?? throw Fail($"{Lte} is not an LTE interface managed by RouterOS (/interface lte). Use Lte.Mode=HiLink for HiLink sticks.");
        var diff = RouterOsStateWriter.Diff(modem, new Props { { "apn-profiles", "itbees" }, { "pin", lte.Pin } });
        await _writer.SetAsync("/interface/lte", modem.Id!, diff, $"{Lte} APN profile and PIN", ct).ConfigureAwait(false);
        await _writer.RemoveStaleAsync("/ip/dhcp-client", "itbees:lte", Array.Empty<string>(), "LTE DHCP client (not used in Modem mode)", ct).ConfigureAwait(false);
        return default;
    }

    /// <summary>
    /// HiLink stick whose DHCP client RouterOS created itself: the backup route and DNS are set in the APN
    /// profile the LTE interface uses, which RouterOS copies to that client.
    /// </summary>
    private async Task<StepOutcome> LteRouterOsDhcpClientAsync(string distance, CancellationToken ct)
    {
        var modem = (await _writer.PrintAsync("/interface/lte", ct, ("name", Lte)).ConfigureAwait(false)).FirstOrDefault();
        var profileName = modem?.Get("apn-profiles")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "default";
        var profile = (await _writer.PrintAsync("/interface/lte/apn", ct, ("name", profileName)).ConfigureAwait(false)).FirstOrDefault()
                      ?? throw Fail($"RouterOS manages the DHCP client on {Lte}, but its APN profile '{profileName}' is missing (/interface lte apn).");
        var desired = new Props
        {
            { "add-default-route", "yes" },
            { "default-route-distance", distance },
            { "use-peer-dns", "no" },
        };
        await _writer.SetAsync(
                "/interface/lte/apn",
                profile.Id!,
                RouterOsStateWriter.Diff(profile, desired),
                $"APN profile {profileName} of {Lte} (HiLink, DHCP client added by RouterOS, backup default route distance {distance})",
                ct)
            .ConfigureAwait(false);

        var managedBy = $"DHCP client added by RouterOS, APN profile {profileName}";
        if (_writer.DryRun)
            return new StepOutcome(managedBy);

        // RouterOS may apply the profile to the running client only after the modem reconnects.
        RouterOsRecord? client = null;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (true)
        {
            client = (await _writer.PrintAsync("/ip/dhcp-client", ct, ("interface", Lte)).ConfigureAwait(false)).FirstOrDefault();
            var current = client?.Get("default-route-distance");
            if (current == null || current == distance || DateTime.UtcNow >= deadline)
                break;
            await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
        }

        var currentDistance = client?.Get("default-route-distance");
        if (currentDistance != null && currentDistance != distance)
            Warn($"The DHCP client on {Lte} still uses route distance {currentDistance} instead of {distance}: RouterOS applies the APN profile when the modem reconnects. Unplug the LTE stick and plug it back in (or reboot the router).");

        var lease = client?.Get("status") == "bound" ? $"{Lte} got {client.Get("address")}" : $"{Lte} lease: {client?.Get("status") ?? "pending"}";
        return new StepOutcome($"{lease} ({managedBy})");
    }

    private async Task<StepOutcome> FailoverAsync(CancellationToken ct)
    {
        var failover = _package.Failover;
        var keepRoutes = new List<string>();
        var keepNetwatch = new List<string>();
        if (failover.Enabled)
        {
            // Until the first lease the check routes point at the interface; the DHCP script fixes the gateway.
            var gateway = _wanGateway ?? Wan;
            for (var i = 0; i < failover.CheckHosts.Count; i++)
            {
                var host = failover.CheckHosts[i];
                var checkComment = RouterOsScripts.WanCheckRoutePrefix + (i + 1);
                var defaultComment = RouterOsScripts.WanDefaultRoutePrefix + (i + 1);
                keepRoutes.Add(checkComment);
                keepRoutes.Add(defaultComment);

                await _writer.EnsureAsync(
                        "/ip/route",
                        new[] { ("comment", checkComment) },
                        new Props { { "dst-address", host + "/32" }, { "gateway", gateway }, { "scope", "10" }, { "comment", checkComment } },
                        $"check host {host} always via {Wan}",
                        ct)
                    .ConfigureAwait(false);
                await _writer.EnsureAsync(
                        "/ip/route",
                        new[] { ("comment", defaultComment) },
                        new Props
                        {
                            { "dst-address", "0.0.0.0/0" },
                            { "gateway", host },
                            { "distance", (i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) },
                            { "check-gateway", "ping" },
                            { "scope", "30" },
                            { "target-scope", "11" },
                            { "comment", defaultComment },
                        },
                        $"primary default route, active while {host} answers via {Wan}",
                        ct)
                    .ConfigureAwait(false);
            }

            // Other static default routes would bypass the failover logic.
            foreach (var row in await _writer.PrintAsync("/ip/route", ct, ("dst-address", "0.0.0.0/0")).ConfigureAwait(false))
            {
                var table = row.Get("routing-table");
                if (row.IsDynamic || (row.Comment?.StartsWith(RouterOsStateWriter.CommentPrefix, StringComparison.Ordinal) ?? false) || (table != null && table != "main"))
                    continue;
                await _writer.RemoveAsync("/ip/route", row.Id!, $"static default route via {row.Get("gateway")} (not managed)", ct).ConfigureAwait(false);
            }

            if (failover.FlushConnectionsOnSwitch)
            {
                const string comment = "itbees:uplink-monitor";
                keepNetwatch.Add(comment);
                await _writer.EnsureAsync(
                        "/tool/netwatch",
                        new[] { ("comment", comment) },
                        new Props
                        {
                            { "host", failover.CheckHosts[0] },
                            { "interval", "10s" },
                            { "up-script", RouterOsScripts.UplinkChangedScript(up: true) },
                            { "down-script", RouterOsScripts.UplinkChangedScript(up: false) },
                            { "disabled", "no" },
                            { "comment", comment },
                        },
                        "uplink change monitor (flushes NAT connections on switch)",
                        ct)
                    .ConfigureAwait(false);
            }
        }

        await _writer.RemoveStaleAsync("/ip/route", "itbees:wan-", keepRoutes, "old failover route", ct).ConfigureAwait(false);
        await _writer.RemoveStaleAsync("/tool/netwatch", "itbees:uplink", keepNetwatch, "old uplink monitor", ct).ConfigureAwait(false);
        if (!failover.Enabled)
            return new StepOutcome("failover disabled: default route from the WAN DHCP lease", Skipped: true);
        return new StepOutcome($"primary checked via {string.Join(", ", failover.CheckHosts)}; LTE distance {_package.Lte.RouteDistance}");
    }

    // ---------------------------------------------------------------- NAT and firewall

    private async Task<StepOutcome> NatAsync(CancellationToken ct)
    {
        await _writer.EnsureAsync(
                "/ip/firewall/nat",
                new[] { ("comment", "itbees:masquerade") },
                new Props { { "chain", "srcnat" }, { "action", "masquerade" }, { "out-interface-list", WanList }, { "comment", "itbees:masquerade" } },
                "masquerade LAN traffic to WAN/LTE",
                ct)
            .ConfigureAwait(false);
        if (_package.Security.RemoveDefconfFirewall)
            await RemoveDefconfAsync("/ip/firewall/nat", ct).ConfigureAwait(false);
        return default;
    }

    private async Task<StepOutcome> FirewallAsync(CancellationToken ct)
    {
        if (!_package.Security.ManageFirewall)
            return new StepOutcome("firewall left unmanaged (Security.ManageFirewall=false)", Skipped: true);

        await EnsureOrderedRulesAsync("/ip/firewall/filter", BuildIpv4Rules(), "IPv4", ct).ConfigureAwait(false);
        try
        {
            await EnsureOrderedRulesAsync("/ipv6/firewall/filter", BuildIpv6Rules(), "IPv6", ct).ConfigureAwait(false);
        }
        catch (MikrotikCommandException e)
        {
            Warn($"IPv6 firewall not configured: {e.RouterMessage}");
        }
        return default;
    }

    private List<(string Comment, Props Props)> BuildIpv4Rules()
    {
        var vpn = _package.Vpn;
        var rules = new List<(string, Props)>
        {
            ("itbees:fw4-in-established", Rule("input", "accept", ("connection-state", "established,related,untracked"))),
            ("itbees:fw4-in-invalid", Rule("input", "drop", ("connection-state", "invalid"))),
            ("itbees:fw4-in-icmp", Rule("input", "accept", ("protocol", "icmp"))),
            ("itbees:fw4-in-loopback", Rule("input", "accept", ("dst-address", "127.0.0.1"))),
            ("itbees:fw4-in-lan", Rule("input", "accept", ("in-interface-list", LanList))),
        };
        // SharedSiteNetwork: the parking subnet arrives on the WAN port; the rest of the site network stays outside.
        if (Shared)
            rules.Add(("itbees:fw4-in-site-lan", Rule("input", "accept", ("in-interface", Wan), ("src-address", _resolved.LanCidr))));
        if (vpn.Enabled)
        {
            // Lets the hub re-initiate the tunnel after an uplink change; WireGuard ignores unauthenticated packets.
            rules.Add(("itbees:fw4-in-wireguard", Rule("input", "accept", ("protocol", "udp"), ("dst-port", vpn.ListenPort.ToString(System.Globalization.CultureInfo.InvariantCulture)))));
            if (vpn.AllowManagement)
                rules.Add(("itbees:fw4-in-vpn", Rule("input", "accept", ("in-interface-list", VpnList))));
        }
        rules.Add(("itbees:fw4-in-drop", Rule("input", "drop")));

        rules.Add(("itbees:fw4-fw-established", Rule("forward", "accept", ("connection-state", "established,related,untracked"))));
        rules.Add(("itbees:fw4-fw-invalid", Rule("forward", "drop", ("connection-state", "invalid"))));
        rules.Add(("itbees:fw4-fw-lan-wan", Rule("forward", "accept", ("in-interface-list", LanList), ("out-interface-list", WanList))));
        if (Shared)
            rules.Add(("itbees:fw4-fw-site-lan-wan", Rule("forward", "accept", ("in-interface", Wan), ("src-address", _resolved.LanCidr), ("out-interface-list", WanList))));
        if (vpn.Enabled && vpn.AllowAccessToLan)
        {
            rules.Add(("itbees:fw4-fw-vpn-lan", Rule("forward", "accept", ("in-interface-list", VpnList), ("out-interface-list", LanList))));
            // Leaves through the WAN port, so the masquerade rule also hides the VPN client behind the router's
            // LAN address: devices answer on-link even with a wrong or missing gateway.
            if (Shared)
                rules.Add(("itbees:fw4-fw-vpn-site-lan", Rule("forward", "accept", ("in-interface-list", VpnList), ("out-interface", Wan), ("dst-address", _resolved.LanCidr))));
        }
        if (vpn.Enabled && vpn.AllowLanToVpn)
        {
            rules.Add(("itbees:fw4-fw-lan-vpn", Rule("forward", "accept", ("in-interface-list", LanList), ("out-interface-list", VpnList))));
            if (Shared)
                rules.Add(("itbees:fw4-fw-site-lan-vpn", Rule("forward", "accept", ("in-interface", Wan), ("src-address", _resolved.LanCidr), ("out-interface-list", VpnList))));
        }
        rules.Add(("itbees:fw4-fw-dstnat", Rule("forward", "accept", ("connection-nat-state", "dstnat"))));
        rules.Add(("itbees:fw4-fw-drop", Rule("forward", "drop")));
        return rules;
    }

    private static List<(string Comment, Props Props)> BuildIpv6Rules() => new()
    {
        ("itbees:fw6-in-established", Rule("input", "accept", ("connection-state", "established,related,untracked"))),
        ("itbees:fw6-in-invalid", Rule("input", "drop", ("connection-state", "invalid"))),
        ("itbees:fw6-in-icmp", Rule("input", "accept", ("protocol", "icmpv6"))),
        ("itbees:fw6-in-lan", Rule("input", "accept", ("in-interface-list", LanList))),
        ("itbees:fw6-in-drop", Rule("input", "drop")),
        ("itbees:fw6-fw-established", Rule("forward", "accept", ("connection-state", "established,related,untracked"))),
        ("itbees:fw6-fw-invalid", Rule("forward", "drop", ("connection-state", "invalid"))),
        ("itbees:fw6-fw-icmp", Rule("forward", "accept", ("protocol", "icmpv6"))),
        ("itbees:fw6-fw-lan-wan", Rule("forward", "accept", ("in-interface-list", LanList), ("out-interface-list", WanList))),
        ("itbees:fw6-fw-drop", Rule("forward", "drop")),
    };

    private static Props Rule(string chain, string action, params (string Name, string Value)[] matchers)
    {
        var props = new Props { { "chain", chain }, { "action", action } };
        foreach (var (name, value) in matchers)
            props.Add(name, value);
        return props;
    }

    /// <summary>
    /// Ensures the managed rules exist and form the top of the table in the given order. Rules are moved one by
    /// one from the top down, so at every moment the accept rules sit above the drop rules (the session is kept).
    /// </summary>
    private async Task EnsureOrderedRulesAsync(string menu, List<(string Comment, Props Props)> rules, string label, CancellationToken ct)
    {
        var all = await _writer.PrintAsync(menu, ct).ConfigureAwait(false);
        var desiredIds = new List<string>();
        foreach (var (comment, props) in rules)
        {
            var matches = all.Where(r => !r.IsDynamic && r.Comment == comment).ToList();
            var values = new Props();
            values.AddRange(props);
            values.Add("comment", comment);
            if (matches.Count == 0)
            {
                desiredIds.Add(await _writer.AddAsync(menu, values, $"{label} rule {comment}", ct).ConfigureAwait(false));
                continue;
            }

            var rule = matches[0];
            var diff = RouterOsStateWriter.Diff(rule, values);
            // Properties the managed rule must not have (e.g. left over from a manual edit) cannot be unset with
            // set; replace such a rule instead.
            var extraMatchers = rule.Keys.Where(k => IsRuleMatcher(k) && values.Get(k) == null && !string.IsNullOrEmpty(rule.Get(k))).ToList();
            if (extraMatchers.Count > 0)
            {
                await _writer.RemoveAsync(menu, rule.Id!, $"{label} rule {comment} (unexpected {string.Join(", ", extraMatchers)})", ct).ConfigureAwait(false);
                desiredIds.Add(await _writer.AddAsync(menu, values, $"{label} rule {comment}", ct).ConfigureAwait(false));
            }
            else
            {
                await _writer.SetAsync(menu, rule.Id!, diff, $"{label} rule {comment}", ct).ConfigureAwait(false);
                desiredIds.Add(rule.Id!);
            }
            foreach (var duplicate in matches.Skip(1))
                await _writer.RemoveAsync(menu, duplicate.Id!, $"{label} rule {comment} (duplicate)", ct).ConfigureAwait(false);
        }

        var wanted = rules.Select(r => r.Comment).ToHashSet(StringComparer.Ordinal);
        var removed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in all.Where(r => !r.IsDynamic && (r.Comment?.StartsWith(RouterOsStateWriter.CommentPrefix, StringComparison.Ordinal) ?? false) && !wanted.Contains(r.Comment!)))
        {
            await _writer.RemoveAsync(menu, row.Id!, $"old {label} rule {row.Comment}", ct).ConfigureAwait(false);
            removed.Add(row.Id!);
        }

        // Current order of static rules (re-read after the writes; simulated in a dry run).
        List<string> order;
        if (_writer.DryRun)
        {
            order = all.Where(r => !r.IsDynamic && !removed.Contains(r.Id!)).Select(r => r.Id!).ToList();
            order.AddRange(desiredIds.Where(id => !order.Contains(id)));
        }
        else
        {
            order = (await _writer.PrintAsync(menu, ct).ConfigureAwait(false)).Where(r => !r.IsDynamic).Select(r => r.Id!).ToList();
        }

        for (var i = 0; i < desiredIds.Count; i++)
        {
            if (i < order.Count && order[i] == desiredIds[i])
                continue;
            var destination = order[i];
            await _writer.MoveAsync(menu, desiredIds[i], destination, $"{label} rule {rules[i].Comment} to position {i + 1}", ct).ConfigureAwait(false);
            order.Remove(desiredIds[i]);
            order.Insert(i, desiredIds[i]);
        }

        if (_package.Security.RemoveDefconfFirewall)
            await RemoveDefconfAsync(menu, ct).ConfigureAwait(false);
    }

    private static bool IsRuleMatcher(string property) => property switch
    {
        ".id" or "chain" or "action" or "comment" or "disabled" or "dynamic" or "invalid" or "bytes" or "packets" or "log" or "log-prefix" => false,
        _ => property.Contains("address") || property.Contains("interface") || property.Contains("port") || property.Contains("state") || property == "protocol",
    };

    private async Task RemoveDefconfAsync(string menu, CancellationToken ct)
    {
        foreach (var row in await _writer.PrintAsync(menu, ct).ConfigureAwait(false))
        {
            if (!row.IsDynamic && (row.Comment?.StartsWith("defconf", StringComparison.Ordinal) ?? false))
                await _writer.RemoveAsync(menu, row.Id!, $"factory rule '{row.Comment}'", ct).ConfigureAwait(false);
        }
    }

    // ---------------------------------------------------------------- services

    private async Task<StepOutcome> ServicesAsync(CancellationToken ct)
    {
        var usesTls = _client is MikrotikClient { Options.UseTls: true };
        var services = await _writer.PrintAsync("/ip/service", ct).ConfigureAwait(false);
        foreach (var name in _package.Security.DisabledServices)
        {
            var row = services.FirstOrDefault(s => s.Get("name") == name);
            if (row == null || row.IsDisabled)
                continue;
            if (name == "api-ssl" && usesTls)
            {
                Warn("api-ssl is in DisabledServices but this session uses it; left enabled.");
                continue;
            }
            await _writer.SetAsync("/ip/service", row.Id!, new Props { { "disabled", "yes" } }, $"disable service {name}", ct).ConfigureAwait(false);
        }

        if (_package.Security.RestrictDiscoveryToLan)
        {
            await TrySingletonAsync("/ip/neighbor/discovery-settings", new Props { { "discover-interface-list", LanList } }, "neighbor discovery only on LAN", ct).ConfigureAwait(false);
            await TrySingletonAsync("/tool/mac-server", new Props { { "allowed-interface-list", LanList } }, "MAC-Telnet only on LAN", ct).ConfigureAwait(false);
            await TrySingletonAsync("/tool/mac-server/mac-winbox", new Props { { "allowed-interface-list", LanList } }, "MAC-Winbox only on LAN", ct).ConfigureAwait(false);
        }
        await TrySingletonAsync("/tool/bandwidth-server", new Props { { "enabled", "no" } }, "bandwidth test server off", ct).ConfigureAwait(false);

        // SharedSiteNetwork: traffic enters and leaves through the same port, so RouterOS would send ICMP redirects
        // pointing the parking devices at the site router. Linux hosts (columns) accept them and would then bypass
        // the router: no LTE failover and no VPN access.
        if (Shared)
            await TrySingletonAsync("/ip/settings", new Props { { "send-redirects", "no" } }, "no ICMP redirects (parking devices must keep the router as gateway)", ct).ConfigureAwait(false);
        return default;
    }

    private async Task TrySingletonAsync(string menu, Props props, string description, CancellationToken ct)
    {
        try
        {
            await _writer.EnsureSingletonAsync(menu, props, description, ct).ConfigureAwait(false);
        }
        catch (MikrotikCommandException e)
        {
            Warn($"{description}: {menu} not available ({e.RouterMessage}).");
        }
    }

    // ---------------------------------------------------------------- VPN

    private async Task<StepOutcome> VpnAsync(CancellationToken ct)
    {
        var vpn = _package.Vpn;
        var name = vpn.InterfaceName;
        if (!vpn.Enabled)
            return await RemoveVpnAsync(ct).ConfigureAwait(false);

        var wgProps = new Props
        {
            { "name", name },
            { "listen-port", vpn.ListenPort.ToString(System.Globalization.CultureInfo.InvariantCulture) },
            { "mtu", vpn.Mtu.ToString(System.Globalization.CultureInfo.InvariantCulture) },
            { "private-key", vpn.PrivateKey },
            { "comment", "itbees:vpn" },
        };
        await _writer.EnsureAsync("/interface/wireguard", new[] { ("name", name) }, wgProps, $"WireGuard interface {name}", ct).ConfigureAwait(false);
        await EnsureListMembersAsync(VpnList, new[] { name }, exclusive: true, ct).ConfigureAwait(false);

        await _writer.EnsureAsync(
                "/ip/address",
                new[] { ("interface", name) },
                new Props { { "address", vpn.Address }, { "interface", name }, { "comment", "itbees:vpn-address" } },
                $"tunnel address {vpn.Address}",
                ct)
            .ConfigureAwait(false);

        var allowed = string.Join(",", _resolved.VpnNetworks.Select(n => n.NetworkCidr));
        await _writer.EnsureAsync(
                "/interface/wireguard/peers",
                new[] { ("interface", name) },
                new Props
                {
                    { "interface", name },
                    { "public-key", vpn.ServerPublicKey },
                    { "endpoint-address", vpn.ServerEndpoint },
                    { "endpoint-port", vpn.ServerPort.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                    { "allowed-address", allowed },
                    { "persistent-keepalive", RouterOsValues.Duration(TimeSpan.FromSeconds(vpn.PersistentKeepaliveSeconds)) },
                    { "preshared-key", vpn.PresharedKey },
                    { "disabled", "no" },
                    { "comment", RouterOsScripts.VpnPeerComment },
                },
                $"VPN hub peer {vpn.ServerEndpoint}:{vpn.ServerPort}",
                ct)
            .ConfigureAwait(false);

        // RouterOS 7 does not route allowed-address automatically; the tunnel's own network is a connected route.
        var tunnel = _resolved.VpnAddress!;
        var connected = new Ipv4Prefix(tunnel.Network, tunnel.PrefixLength);
        var keepRoutes = new List<string>();
        foreach (var network in _resolved.VpnNetworks)
        {
            if (network.PrefixLength >= connected.PrefixLength && connected.Contains(network.Network))
                continue;
            var comment = "itbees:vpn-route-" + network.NetworkCidr;
            keepRoutes.Add(comment);
            await _writer.EnsureAsync(
                    "/ip/route",
                    new[] { ("comment", comment) },
                    new Props { { "dst-address", network.NetworkCidr }, { "gateway", name }, { "comment", comment } },
                    $"route {network.NetworkCidr} through the VPN",
                    ct)
                .ConfigureAwait(false);
        }
        await _writer.RemoveStaleAsync("/ip/route", "itbees:vpn-route-", keepRoutes, "old VPN route", ct).ConfigureAwait(false);

        var watchdogNote = await EnsureWatchdogAsync(vpn, ct).ConfigureAwait(false);

        var wg = (await _writer.PrintAsync("/interface/wireguard", ct, ("name", name)).ConfigureAwait(false)).FirstOrDefault();
        var publicKey = vpn.PrivateKey != null ? WireGuardKeys.GetPublicKey(vpn.PrivateKey) : wg?.Get("public-key");
        _result.VpnInterface = name;
        _result.VpnAddress = vpn.Address;
        _result.VpnPublicKey = publicKey;
        if (publicKey != null)
        {
            var hubAllowed = new List<string> { $"{tunnel.Address}/32" };
            if (vpn.AllowAccessToLan)
                hubAllowed.Add(_resolved.LanCidr);
            var peerName = _package.Identity ?? _result.Device?.Identity ?? _result.Device?.SerialNumber ?? _client.Host;
            _result.VpnHubPeer = new WireGuardHubPeer(peerName, publicKey, vpn.PresharedKey, hubAllowed);
        }
        else
        {
            Warn("The router's WireGuard public key is not known yet (dry run); it is returned after a real apply.");
        }
        return new StepOutcome($"{name} {vpn.Address} -> {vpn.ServerEndpoint}:{vpn.ServerPort}{(watchdogNote != null ? "; " + watchdogNote : string.Empty)}");
    }

    /// <summary>Installs the watchdog script and what runs it every minute; returns a note when netwatch runs it.</summary>
    private async Task<string?> EnsureWatchdogAsync(VpnSettings vpn, CancellationToken ct)
    {
        const string name = RouterOsScripts.VpnWatchdogName;
        if (!vpn.Watchdog)
        {
            await RemoveWatchdogAsync(ct).ConfigureAwait(false);
            return null;
        }
        await _writer.EnsureAsync(
                "/system/script",
                new[] { ("name", name) },
                new Props
                {
                    { "name", name },
                    { "source", RouterOsScripts.VpnWatchdogScript(vpn.WatchdogHandshakeTimeoutSeconds) },
                    { "policy", "read,write,test" },
                    { "dont-require-permissions", "no" },
                    { "comment", "itbees:vpn-watchdog" },
                },
                "VPN watchdog script",
                ct)
            .ConfigureAwait(false);

        if (_schedulerAllowed)
        {
            await _writer.EnsureAsync(
                    "/system/scheduler",
                    new[] { ("name", name) },
                    new Props
                    {
                        { "name", name },
                        { "on-event", name },
                        { "interval", "1m" },
                        { "start-time", "startup" },
                        { "policy", "read,write,test" },
                        { "disabled", "no" },
                        { "comment", "itbees:vpn-watchdog" },
                    },
                    "VPN watchdog schedule (every minute)",
                    ct)
                .ConfigureAwait(false);
            await _writer.RemoveStaleAsync("/tool/netwatch", "itbees:vpn-watchdog", Array.Empty<string>(), "VPN watchdog in netwatch (the scheduler runs it)", ct).ConfigureAwait(false);
            return null;
        }

        // Device-mode blocks the scheduler but not netwatch, which runs test-script after every probe. The probe
        // targets the router's own tunnel address, so it always answers and only serves as a one-minute timer.
        await _writer.EnsureAsync(
                "/tool/netwatch",
                new[] { ("comment", "itbees:vpn-watchdog") },
                new Props
                {
                    { "host", _resolved.VpnAddress!.Address.ToString() },
                    { "type", "simple" },
                    { "interval", "1m" },
                    { "test-script", $"/system script run {name}" },
                    { "disabled", "no" },
                    { "comment", "itbees:vpn-watchdog" },
                },
                $"VPN watchdog every minute from netwatch (device-mode {_deviceMode ?? "?"} blocks the scheduler)",
                ct)
            .ConfigureAwait(false);
        return $"watchdog run by netwatch (device-mode {_deviceMode ?? "?"} blocks the scheduler)";
    }

    private async Task RemoveWatchdogAsync(CancellationToken ct)
    {
        // With the scheduler blocked by device-mode there is nothing of ours to remove there.
        if (_schedulerAllowed)
            await RemoveByNameAsync("/system/scheduler", RouterOsScripts.VpnWatchdogName, ct).ConfigureAwait(false);
        await _writer.RemoveStaleAsync("/tool/netwatch", "itbees:vpn-watchdog", Array.Empty<string>(), "VPN watchdog in netwatch", ct).ConfigureAwait(false);
        await RemoveByNameAsync("/system/script", RouterOsScripts.VpnWatchdogName, ct).ConfigureAwait(false);
    }

    private async Task<StepOutcome> RemoveVpnAsync(CancellationToken ct)
    {
        var managed = (await _writer.PrintAsync("/interface/wireguard", ct).ConfigureAwait(false)).Where(r => r.Comment == "itbees:vpn").ToList();
        if (managed.Count == 0)
            return new StepOutcome("VPN disabled in the package", Skipped: true);

        foreach (var wg in managed)
        {
            var name = wg.Get("name")!;
            if (name == _managementInterface)
                throw Fail($"The package disables the VPN but this session runs over {name}. Apply it from the LAN instead.");
            foreach (var peer in await _writer.PrintAsync("/interface/wireguard/peers", ct, ("interface", name)).ConfigureAwait(false))
                await _writer.RemoveAsync("/interface/wireguard/peers", peer.Id!, $"VPN peer on {name}", ct).ConfigureAwait(false);
            foreach (var address in await _writer.PrintAsync("/ip/address", ct, ("interface", name)).ConfigureAwait(false))
                if (!address.IsDynamic)
                    await _writer.RemoveAsync("/ip/address", address.Id!, $"tunnel address {address.Get("address")}", ct).ConfigureAwait(false);
            foreach (var member in await _writer.PrintAsync("/interface/list/member", ct, ("interface", name)).ConfigureAwait(false))
                if (!member.IsDynamic)
                    await _writer.RemoveAsync("/interface/list/member", member.Id!, $"{name} out of list {member.Get("list")}", ct).ConfigureAwait(false);
            await _writer.RemoveStaleAsync("/ip/route", "itbees:vpn-route-", Array.Empty<string>(), "VPN route", ct).ConfigureAwait(false);
            await _writer.RemoveAsync("/interface/wireguard", wg.Id!, $"WireGuard interface {name}", ct).ConfigureAwait(false);
        }
        await RemoveWatchdogAsync(ct).ConfigureAwait(false);
        return new StepOutcome("VPN removed (disabled in the package)");
    }

    private async Task RemoveByNameAsync(string menu, string name, CancellationToken ct)
    {
        foreach (var row in await _writer.PrintAsync(menu, ct, ("name", name)).ConfigureAwait(false))
            await _writer.RemoveAsync(menu, row.Id!, $"{name}", ct).ConfigureAwait(false);
    }

    // ---------------------------------------------------------------- LAN DHCP, password, LAN address

    private async Task<StepOutcome> LanDhcpAsync(CancellationToken ct)
    {
        var dhcp = _package.Lan.Dhcp;
        var routerIp = _resolved.LanRouterIp;
        var servers = (await _writer.PrintAsync("/ip/dhcp-server", ct, ("interface", Bridge)).ConfigureAwait(false)).Where(r => !r.IsDynamic).ToList();

        if (Shared)
        {
            // A DHCP server on the WAN port would answer the site's own devices; none may run there.
            servers.AddRange((await _writer.PrintAsync("/ip/dhcp-server", ct, ("interface", Wan)).ConfigureAwait(false)).Where(r => !r.IsDynamic));
        }

        if (!dhcp.Enabled)
        {
            foreach (var server in servers.Where(s => !s.IsDisabled))
                await _writer.SetAsync("/ip/dhcp-server", server.Id!, new Props { { "disabled", "yes" } }, $"disable DHCP server {server.Get("name")}", ct).ConfigureAwait(false);
            await EnsureRouterDnsNameAsync(routerIp, ct).ConfigureAwait(false);
            return Shared
                ? new StepOutcome($"no DHCP server (shared site network): parking devices use static addresses in {_resolved.LanCidr} with gateway {routerIp}")
                : new StepOutcome("DHCP server disabled in the package", Skipped: servers.Count == 0);
        }

        const string poolName = "itbees-lan";
        await _writer.EnsureAsync("/ip/pool", new[] { ("name", poolName) }, new Props { { "name", poolName }, { "ranges", _resolved.PoolRange }, { "comment", "itbees:lan-pool" } }, $"LAN pool {_resolved.PoolRange}", ct)
            .ConfigureAwait(false);

        var dnsForClients = _package.Dns.AllowRemoteRequests ? routerIp : string.Join(",", _package.Dns.Servers);
        await _writer.EnsureAsync(
                "/ip/dhcp-server/network",
                new[] { ("address", _resolved.LanCidr) },
                new Props { { "address", _resolved.LanCidr }, { "gateway", routerIp }, { "dns-server", dnsForClients }, { "comment", "itbees:lan" } },
                $"DHCP network {_resolved.LanCidr}",
                ct)
            .ConfigureAwait(false);
        foreach (var network in await _writer.PrintAsync("/ip/dhcp-server/network", ct).ConfigureAwait(false))
        {
            if (!network.IsDynamic && network.Get("address") != _resolved.LanCidr)
                await _writer.RemoveAsync("/ip/dhcp-server/network", network.Id!, $"old DHCP network {network.Get("address")}", ct).ConfigureAwait(false);
        }

        var leaseTime = RouterOsValues.Duration(TimeSpan.FromHours(dhcp.LeaseTimeHours));
        string serverName;
        if (servers.Count == 0)
        {
            serverName = "itbees-lan";
            await _writer.AddAsync(
                    "/ip/dhcp-server",
                    new Props { { "name", serverName }, { "interface", Bridge }, { "address-pool", poolName }, { "lease-time", leaseTime }, { "disabled", "no" }, { "comment", "itbees:lan-dhcp" } },
                    $"DHCP server on {Bridge}",
                    ct)
                .ConfigureAwait(false);
        }
        else
        {
            serverName = servers[0].Get("name")!;
            var diff = RouterOsStateWriter.Diff(servers[0], new Props { { "address-pool", poolName }, { "lease-time", leaseTime }, { "disabled", "no" } });
            await _writer.SetAsync("/ip/dhcp-server", servers[0].Id!, diff, $"DHCP server {serverName} on {Bridge}", ct).ConfigureAwait(false);
            foreach (var extra in servers.Skip(1))
                await _writer.RemoveAsync("/ip/dhcp-server", extra.Id!, $"second DHCP server {extra.Get("name")} on {Bridge}", ct).ConfigureAwait(false);
        }

        await EnsureStaticLeasesAsync(serverName, ct).ConfigureAwait(false);

        // The factory pool is dropped once no DHCP server other than the LAN one (now on our pool) uses it.
        var lanServerIds = servers.Select(s => s.Id).ToHashSet();
        var otherServers = (await _writer.PrintAsync("/ip/dhcp-server", ct).ConfigureAwait(false)).Where(s => !lanServerIds.Contains(s.Id)).ToList();
        foreach (var pool in await _writer.PrintAsync("/ip/pool", ct, ("name", "default-dhcp")).ConfigureAwait(false))
        {
            if (otherServers.All(s => s.Get("address-pool") != "default-dhcp"))
                await _writer.RemoveAsync("/ip/pool", pool.Id!, "factory pool default-dhcp (unused)", ct).ConfigureAwait(false);
        }

        await EnsureRouterDnsNameAsync(routerIp, ct).ConfigureAwait(false);
        return new StepOutcome($"{_resolved.LanCidr}, pool {_resolved.PoolRange}, {dhcp.StaticLeases.Count} static lease(s)");
    }

    private async Task EnsureRouterDnsNameAsync(string routerIp, CancellationToken ct)
    {
        if (_package.Lan.RouterDnsName == null)
            return;
        await _writer.EnsureAsync(
                "/ip/dns/static",
                new[] { ("name", _package.Lan.RouterDnsName) },
                new Props { { "name", _package.Lan.RouterDnsName }, { "address", routerIp } },
                $"DNS name {_package.Lan.RouterDnsName} -> {routerIp}",
                ct,
                addOnly: new Props { { "comment", "itbees:router-name" } })
            .ConfigureAwait(false);
    }

    private async Task EnsureStaticLeasesAsync(string serverName, CancellationToken ct)
    {
        const string prefix = "itbees:lease";
        var leases = await _writer.PrintAsync("/ip/dhcp-server/lease", ct).ConfigureAwait(false);
        var desiredMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var lease in _package.Lan.Dhcp.StaticLeases)
        {
            var mac = Discovery.MikrotikNeighbor.FormatMac(Discovery.LinkLocal.ParseMac(lease.MacAddress));
            desiredMacs.Add(mac);
            var comment = string.IsNullOrWhiteSpace(lease.Comment) ? prefix : $"{prefix} {lease.Comment.Trim()}";
            var existing = leases.Where(r => string.Equals(r.Get("mac-address"), mac, StringComparison.OrdinalIgnoreCase)).ToList();
            foreach (var dynamicLease in existing.Where(r => r.IsDynamic))
                await _writer.RemoveAsync("/ip/dhcp-server/lease", dynamicLease.Id!, $"dynamic lease of {mac} (replaced by a static one)", ct).ConfigureAwait(false);

            var props = new Props { { "address", lease.Address }, { "mac-address", mac }, { "server", serverName }, { "comment", comment } };
            var current = existing.FirstOrDefault(r => !r.IsDynamic);
            if (current == null)
                await _writer.AddAsync("/ip/dhcp-server/lease", props, $"static lease {lease.Address} for {mac}", ct).ConfigureAwait(false);
            else
                await _writer.SetAsync("/ip/dhcp-server/lease", current.Id!, RouterOsStateWriter.Diff(current, props), $"static lease {lease.Address} for {mac}", ct).ConfigureAwait(false);
        }

        foreach (var row in leases)
        {
            if (row.IsDynamic || !(row.Comment?.StartsWith(prefix, StringComparison.Ordinal) ?? false) || desiredMacs.Contains(row.Get("mac-address") ?? string.Empty))
                continue;
            await _writer.RemoveAsync("/ip/dhcp-server/lease", row.Id!, $"old static lease {row.Get("address")} ({row.Get("mac-address")})", ct).ConfigureAwait(false);
        }
    }

    private async Task<StepOutcome> PasswordAsync(CancellationToken ct)
    {
        var newPassword = _package.Security.AdminPassword;
        if (string.IsNullOrEmpty(newPassword))
            return new StepOutcome("keeping the current password", Skipped: true);

        var client = _client as MikrotikClient;
        if (client != null && client.Options.Password == newPassword)
            return new StepOutcome($"'{_client.Username}' already uses the package password");

        var user = (await _writer.PrintAsync("/user", ct, ("name", _client.Username)).ConfigureAwait(false)).FirstOrDefault()
                   ?? throw Fail($"User '{_client.Username}' not found on the router.");
        await _writer.SetAsync("/user", user.Id!, new Props { { "password", newPassword } }, $"new password for '{_client.Username}'", ct).ConfigureAwait(false);
        if (_writer.DryRun)
            return default;

        if (client != null && _options.VerifyNewPassword)
        {
            if (!await client.VerifyPasswordAsync(newPassword, ct).ConfigureAwait(false))
            {
                await _writer.SetAsync("/user", user.Id!, new Props { { "password", client.Options.Password } }, $"restore the previous password of '{_client.Username}'", ct).ConfigureAwait(false);
                throw Fail("The router did not accept the new password on a fresh login; the previous password was restored.");
            }
        }
        client?.UpdatePassword(newPassword);
        _result.PasswordChanged = true;
        return new StepOutcome($"password of '{_client.Username}' changed{(client != null && _options.VerifyNewPassword ? " and verified" : string.Empty)}");
    }

    private async Task<StepOutcome> LanAddressAsync(CancellationToken ct)
    {
        const string comment = LanAddressComment;
        var desired = _package.Lan.Address;
        _result.LanRouterAddress = _resolved.LanRouterIp;
        if (Shared)
            return await SharedLanAddressAsync(ct).ConfigureAwait(false);
        var rows = (await _writer.PrintAsync("/ip/address", ct, ("interface", Bridge)).ConfigureAwait(false)).Where(r => !r.IsDynamic).ToList();
        var exact = rows.FirstOrDefault(r => r.Get("address") == desired);
        var sessionRow = _sessionAddress == null
            ? null
            : rows.FirstOrDefault(r => Ipv4Prefix.TryParse(r.Get("address"), out var p) && p.Address.Equals(_sessionAddress));

        if (exact != null)
        {
            if (exact.Comment != comment)
                await _writer.SetAsync("/ip/address", exact.Id!, new Props { { "comment", comment } }, $"mark LAN address {desired}", ct).ConfigureAwait(false);
            foreach (var extra in rows.Where(r => r != exact && r != sessionRow))
                await _writer.RemoveAsync("/ip/address", extra.Id!, $"old LAN address {extra.Get("address")}", ct).ConfigureAwait(false);
            if (sessionRow != null && sessionRow != exact)
            {
                await FinalCommandAsync(
                        token => _writer.RemoveAsync("/ip/address", sessionRow.Id!, $"old LAN address {sessionRow.Get("address")} (this session's address)", token),
                        ct)
                    .ConfigureAwait(false);
            }
            return default;
        }

        if (rows.Count == 0)
        {
            await _writer.AddAsync("/ip/address", new Props { { "address", desired }, { "interface", Bridge }, { "comment", comment } }, $"LAN address {desired}", ct).ConfigureAwait(false);
            return default;
        }

        var target = sessionRow ?? rows[0];
        foreach (var extra in rows.Where(r => r != target))
            await _writer.RemoveAsync("/ip/address", extra.Id!, $"old LAN address {extra.Get("address")}", ct).ConfigureAwait(false);

        var change = new Props { { "address", desired }, { "comment", comment } };
        if (target == sessionRow && _sessionViaLanIpv4)
        {
            await FinalCommandAsync(token => _writer.SetAsync("/ip/address", target.Id!, change, $"LAN address {target.Get("address")} -> {desired} (this session's address)", token), ct)
                .ConfigureAwait(false);
        }
        else
        {
            await _writer.SetAsync("/ip/address", target.Id!, change, $"LAN address {target.Get("address")} -> {desired}", ct).ConfigureAwait(false);
        }
        return new StepOutcome(_result.ReconnectRequired ? $"router now at {_resolved.LanRouterIp}; reconnect" : $"router at {_resolved.LanRouterIp}");
    }

    /// <summary>
    /// SharedSiteNetwork: the LAN address goes on the WAN port, next to the site DHCP lease. The bridge (service
    /// ports) keeps no IPv4 address, so the same subnet never sits on two interfaces and a factory 192.168.88.1
    /// cannot clash with a site network that uses the MikroTik default subnet. This session's address goes last.
    /// </summary>
    private async Task<StepOutcome> SharedLanAddressAsync(CancellationToken ct)
    {
        var desired = _package.Lan.Address;
        bool IsSession(RouterOsRecord row) =>
            _sessionAddress != null && Ipv4Prefix.TryParse(row.Get("address"), out var p) && p.Address.Equals(_sessionAddress);

        var bridgeRows = (await _writer.PrintAsync("/ip/address", ct, ("interface", Bridge)).ConfigureAwait(false)).Where(r => !r.IsDynamic).ToList();
        var sessionBridgeRow = bridgeRows.FirstOrDefault(IsSession);
        foreach (var row in bridgeRows.Where(r => r != sessionBridgeRow))
            await _writer.RemoveAsync("/ip/address", row.Id!, $"address {row.Get("address")} from {Bridge} (the parking subnet is on {Wan})", ct).ConfigureAwait(false);

        var wanRows = (await _writer.PrintAsync("/ip/address", ct, ("interface", Wan)).ConfigureAwait(false)).Where(r => !r.IsDynamic).ToList();
        var exact = wanRows.FirstOrDefault(r => r.Get("address") == desired);
        if (exact == null)
            await _writer.AddAsync("/ip/address", new Props { { "address", desired }, { "interface", Wan }, { "comment", LanAddressComment } }, $"LAN address {desired} on {Wan}", ct).ConfigureAwait(false);
        else if (exact.Comment != LanAddressComment)
            await _writer.SetAsync("/ip/address", exact.Id!, new Props { { "comment", LanAddressComment } }, $"mark LAN address {desired} on {Wan}", ct).ConfigureAwait(false);

        // Old LAN addresses on the WAN port (e.g. after a change of the parking subnet).
        var oldRows = wanRows.Where(r => r != exact && r.Comment == LanAddressComment).ToList();
        foreach (var row in oldRows.Where(r => !IsSession(r)))
            await _writer.RemoveAsync("/ip/address", row.Id!, $"old LAN address {row.Get("address")} from {Wan}", ct).ConfigureAwait(false);

        var sessionRow = sessionBridgeRow ?? oldRows.FirstOrDefault(IsSession);
        if (sessionRow != null)
        {
            await FinalCommandAsync(
                    token => _writer.RemoveAsync("/ip/address", sessionRow.Id!, $"address {sessionRow.Get("address")} from {sessionRow.Get("interface")} (this session's address)", token),
                    ct,
                    cutsSession: true)
                .ConfigureAwait(false);
        }
        return new StepOutcome(_result.ReconnectRequired
            ? $"router now at {_resolved.LanRouterIp} on {Wan}; reconnect from the site network"
            : $"router at {_resolved.LanRouterIp} on {Wan}");
    }

    /// <summary>Runs the command that removes this session's address: the reply usually never arrives.</summary>
    private async Task FinalCommandAsync(Func<CancellationToken, Task> command, CancellationToken ct, bool? cutsSession = null)
    {
        if (_writer.DryRun || !(cutsSession ?? _sessionViaLanIpv4))
        {
            await command(ct).ConfigureAwait(false);
            return;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.LanSwitchReplyTimeout);
        try
        {
            await command(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            _logger.LogInformation("No reply after re-addressing the LAN (expected: the session used the old address).");
        }
        catch (MikrotikConnectionException e)
        {
            _logger.LogInformation("Session closed after re-addressing the LAN (expected): {Message}", e.Message);
        }
        _result.ReconnectRequired = true;
        Warn(Shared
            ? $"The router is now at {_resolved.LanRouterIp} on {Wan} (shared site network) and this session used an address it no longer has. Connect the computer back to the site network with a static address in {_resolved.LanCidr} (gateway {_resolved.LanRouterIp}) and reconnect to verify."
            : $"The LAN address changed to {_resolved.LanRouterIp} and this session used the old one. Renew the computer's DHCP lease (or use the IPv6 link-local / VPN address) and reconnect to verify.");
    }

    private void Warn(string message)
    {
        _result.Warnings.Add(message);
        _logger.LogWarning("{Message}", message);
    }

    private MikrotikException Fail(string message) => new(_client.Host, message);

    private readonly record struct StepOutcome(string? Message = null, bool Skipped = false);
}
