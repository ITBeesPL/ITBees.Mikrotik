using System.Globalization;
using ITBees.Mikrotik.Api;
using ITBees.Mikrotik.Configuration;

namespace ITBees.Mikrotik.Status;

public enum MikrotikUplink
{
    Unknown,

    /// <summary>Internet goes through the primary link (ether1, site network).</summary>
    Primary,

    /// <summary>Internet goes through the LTE modem (failover active).</summary>
    Backup,

    /// <summary>No active default route: no internet.</summary>
    None,
}

public sealed record MikrotikWanStatus(string Interface, bool Running, string? DhcpStatus, string? Address, string? Gateway);

public sealed record MikrotikLteStatus(
    bool Detected,
    string Interface,
    bool Running,
    string? Address,
    string? Gateway,
    string? RegistrationStatus,
    string? Operator,
    string? AccessTechnology,
    int? Rssi,
    int? Rsrp,
    int? Rsrq,
    int? Sinr);

public sealed record MikrotikVpnStatus(
    bool Configured,
    string? Interface,
    bool Running,
    string? Address,
    string? PublicKey,
    string? Endpoint,
    string? CurrentEndpoint,
    TimeSpan? LastHandshake,
    long? RxBytes,
    long? TxBytes)
{
    /// <summary>A handshake within the last 3 minutes (WireGuard re-handshakes every 2 minutes while traffic flows).</summary>
    public bool IsConnected => LastHandshake != null && LastHandshake < TimeSpan.FromMinutes(3);
}

/// <summary>Snapshot of a parking router: what the operator assigned, which link carries traffic, tunnel state.</summary>
public sealed record MikrotikStatus(
    MikrotikDeviceInfo Device,
    MikrotikWanStatus Wan,
    MikrotikLteStatus Lte,
    MikrotikUplink ActiveUplink,
    string? ActiveGateway,
    MikrotikVpnStatus Vpn,
    DateTimeOffset ReadAt)
{
    public override string ToString() =>
        $"{Device.Identity}: uplink {ActiveUplink} ({ActiveGateway ?? "-"}), WAN {Wan.DhcpStatus ?? "-"} {Wan.Address ?? "-"}, " +
        $"LTE {(Lte.Detected ? Lte.Address ?? Lte.RegistrationStatus ?? "detected" : "not detected")}, " +
        $"VPN {(Vpn.Configured ? (Vpn.IsConnected ? "up" : "down") : "off")}";
}

/// <summary>Reads <see cref="MikrotikStatus"/>; interface names come from the package (defaults when null).</summary>
public sealed class MikrotikStatusReader
{
    public async Task<MikrotikStatus> ReadAsync(IMikrotikClient client, MikrotikConfigurationPackage? package = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        package ??= new MikrotikConfigurationPackage();
        var api = client.Api;
        var device = await client.RefreshDeviceInfoAsync(cancellationToken).ConfigureAwait(false);
        var interfaces = (await PrintAsync(api, "/interface", cancellationToken).ConfigureAwait(false))
            .Where(i => i.Get("name") != null)
            .GroupBy(i => i.Get("name")!)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

        // The link is the WAN port's; the lease and the primary route are on the bridge in SharedSiteNetwork mode.
        var wanName = package.Wan.Interface;
        var leaseInterface = package.WanAddressInterface;
        var wanLease = (await PrintAsync(api, "/ip/dhcp-client", cancellationToken, ("interface", leaseInterface)).ConfigureAwait(false)).FirstOrDefault();
        var wan = new MikrotikWanStatus(
            wanName,
            interfaces.TryGetValue(wanName, out var wanInterface) && wanInterface.GetBool("running") == true,
            wanLease?.Get("status"),
            wanLease?.Get("address"),
            wanLease?.Get("gateway"));

        var lte = await ReadLteAsync(api, package.Lte.Interface, interfaces, cancellationToken).ConfigureAwait(false);
        var (uplink, gateway) = await ReadUplinkAsync(api, leaseInterface, lte, cancellationToken).ConfigureAwait(false);
        var vpn = await ReadVpnAsync(api, package.Vpn.InterfaceName, interfaces, cancellationToken).ConfigureAwait(false);
        return new MikrotikStatus(device, wan, lte, uplink, gateway, vpn, DateTimeOffset.Now);
    }

    private static async Task<MikrotikLteStatus> ReadLteAsync(IRouterOsApiConnection api, string name, Dictionary<string, RouterOsRecord> interfaces, CancellationToken ct)
    {
        if (!interfaces.TryGetValue(name, out var lteInterface))
            return new MikrotikLteStatus(false, name, false, null, null, null, null, null, null, null, null, null);

        string? address = null;
        string? gateway = null;
        var lease = (await PrintAsync(api, "/ip/dhcp-client", ct, ("interface", name)).ConfigureAwait(false)).FirstOrDefault();
        if (lease != null)
        {
            address = lease.Get("address");
            gateway = lease.Get("gateway");
        }
        else
        {
            address = (await PrintAsync(api, "/ip/address", ct, ("interface", name)).ConfigureAwait(false)).FirstOrDefault()?.Get("address");
        }

        RouterOsRecord? monitor = null;
        try
        {
            // Works for modems driven by RouterOS; HiLink sticks usually report nothing useful here.
            monitor = (await api.ExecuteAsync(new RouterOsCommand("/interface/lte/monitor").With("numbers", name).With("once", string.Empty), ct).ConfigureAwait(false)).Records.FirstOrDefault();
        }
        catch (MikrotikCommandException)
        {
        }

        return new MikrotikLteStatus(
            true,
            name,
            lteInterface.GetBool("running") == true,
            address,
            gateway,
            monitor?.Get("registration-status"),
            monitor?.Get("current-operator"),
            monitor?.Get("access-technology"),
            ParseSignal(monitor?.Get("rssi")),
            ParseSignal(monitor?.Get("rsrp")),
            ParseSignal(monitor?.Get("rsrq")),
            ParseSignal(monitor?.Get("sinr")));
    }

    private static async Task<(MikrotikUplink, string?)> ReadUplinkAsync(IRouterOsApiConnection api, string wan, MikrotikLteStatus lte, CancellationToken ct)
    {
        var routes = (await PrintAsync(api, "/ip/route", ct, ("dst-address", "0.0.0.0/0")).ConfigureAwait(false))
            .Where(r => r.GetBool("active") == true && (r.Get("routing-table") ?? "main") == "main")
            .ToList();
        if (routes.Count == 0)
            return (MikrotikUplink.None, null);

        var route = routes[0];
        var immediate = route.Get("immediate-gw") ?? string.Empty;
        var gateway = route.Get("gateway");
        if (route.Comment?.StartsWith("itbees:wan-default", StringComparison.Ordinal) == true || immediate.EndsWith("%" + wan, StringComparison.Ordinal))
            return (MikrotikUplink.Primary, string.IsNullOrEmpty(immediate) ? gateway : immediate);
        if (immediate.EndsWith("%" + lte.Interface, StringComparison.Ordinal) || gateway == lte.Interface || (lte.Gateway != null && gateway == lte.Gateway))
            return (MikrotikUplink.Backup, string.IsNullOrEmpty(immediate) ? gateway : immediate);
        return (MikrotikUplink.Unknown, string.IsNullOrEmpty(immediate) ? gateway : immediate);
    }

    private static async Task<MikrotikVpnStatus> ReadVpnAsync(IRouterOsApiConnection api, string name, Dictionary<string, RouterOsRecord> interfaces, CancellationToken ct)
    {
        RouterOsRecord? wg;
        try
        {
            var all = await PrintAsync(api, "/interface/wireguard", ct).ConfigureAwait(false);
            wg = all.FirstOrDefault(w => w.Get("name") == name) ?? all.FirstOrDefault(w => w.Comment == "itbees:vpn");
        }
        catch (MikrotikCommandException)
        {
            wg = null;
        }
        if (wg == null)
            return new MikrotikVpnStatus(false, null, false, null, null, null, null, null, null, null);

        var wgName = wg.Get("name")!;
        var peer = (await PrintAsync(api, "/interface/wireguard/peers", ct, ("interface", wgName)).ConfigureAwait(false)).FirstOrDefault();
        var address = (await PrintAsync(api, "/ip/address", ct, ("interface", wgName)).ConfigureAwait(false)).FirstOrDefault()?.Get("address");
        var endpoint = peer?.Get("endpoint-address");
        var current = peer?.Get("current-endpoint-address");
        return new MikrotikVpnStatus(
            true,
            wgName,
            interfaces.TryGetValue(wgName, out var row) ? row.GetBool("running") == true : wg.GetBool("running") == true,
            address,
            wg.Get("public-key"),
            endpoint == null ? null : $"{endpoint}:{peer?.Get("endpoint-port")}",
            string.IsNullOrEmpty(current) ? null : $"{current}:{peer?.Get("current-endpoint-port")}",
            peer?.GetDuration("last-handshake"),
            peer?.GetLong("rx"),
            peer?.GetLong("tx"));
    }

    private static int? ParseSignal(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var digits = new string(value.Trim().TakeWhile(c => char.IsDigit(c) || c == '-').ToArray());
        return int.TryParse(digits, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number) ? number : null;
    }

    private static async Task<IReadOnlyList<RouterOsRecord>> PrintAsync(IRouterOsApiConnection api, string menu, CancellationToken ct, params (string Name, string Value)[] where)
    {
        var command = new RouterOsCommand(menu + "/print");
        foreach (var (name, value) in where)
            command.Where(name, value);
        return (await api.ExecuteAsync(command, ct).ConfigureAwait(false)).Records;
    }
}
