using System.Net;
using ITBees.Mikrotik.WireGuard;

namespace ITBees.Mikrotik.Configuration;

public sealed class MikrotikValidationResult
{
    public MikrotikValidationResult(IReadOnlyList<string> errors, IReadOnlyList<string> warnings)
    {
        Errors = errors;
        Warnings = warnings;
    }

    public IReadOnlyList<string> Errors { get; }

    public IReadOnlyList<string> Warnings { get; }

    public bool IsValid => Errors.Count == 0;

    /// <exception cref="MikrotikConfigurationException">When there are errors.</exception>
    public void ThrowIfInvalid()
    {
        if (!IsValid)
            throw new MikrotikConfigurationException(Errors);
    }
}

/// <summary>Values derived from a package (pool range, tunnel networks, ...), shared by the validator and the provisioner.</summary>
internal sealed class ResolvedPackage
{
    public required Ipv4Prefix Lan { get; init; }

    public required IPAddress PoolStart { get; init; }

    public required IPAddress PoolEnd { get; init; }

    public Ipv4Prefix? VpnAddress { get; init; }

    public IReadOnlyList<Ipv4Prefix> VpnNetworks { get; init; } = Array.Empty<Ipv4Prefix>();

    public string LanRouterIp => Lan.Address.ToString();

    public string LanCidr => Lan.NetworkCidr;

    public string PoolRange => $"{PoolStart}-{PoolEnd}";
}

public static class MikrotikConfigurationValidator
{
    public const int MinimumPasswordLength = 8;
    public const int MaxIdentityLength = 64;

    public static MikrotikValidationResult Validate(MikrotikConfigurationPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);
        var errors = new List<string>();
        var warnings = new List<string>();

        if (package.SchemaVersion != MikrotikConfigurationPackage.CurrentSchemaVersion)
            errors.Add($"SchemaVersion {package.SchemaVersion} is not supported (expected {MikrotikConfigurationPackage.CurrentSchemaVersion}).");
        if (package.Identity != null && (package.Identity.Trim().Length == 0 || package.Identity.Length > MaxIdentityLength))
            errors.Add($"Identity must be 1-{MaxIdentityLength} characters.");

        ValidateSecurity(package.Security, errors, warnings);
        var interfaces = ValidateInterfaces(package, errors);
        var lan = ValidateLan(package.Lan, errors, warnings, out var poolStart, out var poolEnd);
        ValidateDns(package, errors);
        ValidateFailover(package, lan, errors);
        ValidateLte(package.Lte, lan, errors);
        ValidateVpn(package, lan, errors, warnings);

        if (package.Dns.AllowRemoteRequests && !package.Security.ManageFirewall)
            warnings.Add("Dns.AllowRemoteRequests with Security.ManageFirewall=false: make sure DNS (port 53) is blocked from WAN, otherwise the router is an open resolver.");
        if (interfaces.Count == 0)
            errors.Add("No interfaces configured.");

        return new MikrotikValidationResult(errors, warnings);
    }

    internal static ResolvedPackage Resolve(MikrotikConfigurationPackage package)
    {
        Validate(package).ThrowIfInvalid();
        var lan = Ipv4Prefix.Parse(package.Lan.Address);
        var (start, end) = ResolvePool(package.Lan.Dhcp, lan);
        Ipv4Prefix? vpnAddress = null;
        var vpnNetworks = new List<Ipv4Prefix>();
        if (package.Vpn.Enabled)
        {
            vpnAddress = Ipv4Prefix.Parse(package.Vpn.Address!);
            vpnNetworks.AddRange(package.Vpn.AllowedAddresses.Count > 0
                ? package.Vpn.AllowedAddresses.Select(Ipv4Prefix.Parse).Select(p => new Ipv4Prefix(p.Network, p.PrefixLength))
                : new[] { new Ipv4Prefix(vpnAddress.Network, vpnAddress.PrefixLength) });
        }
        return new ResolvedPackage { Lan = lan, PoolStart = start, PoolEnd = end, VpnAddress = vpnAddress, VpnNetworks = vpnNetworks };
    }

    private static void ValidateSecurity(SecuritySettings security, List<string> errors, List<string> warnings)
    {
        if (string.IsNullOrEmpty(security.AdminPassword))
        {
            if (!security.KeepCurrentPassword)
                errors.Add("Security.AdminPassword is required (the factory password must be replaced). Set Security.KeepCurrentPassword=true to keep the current one.");
        }
        else
        {
            if (security.AdminPassword.Length < MinimumPasswordLength)
                errors.Add($"Security.AdminPassword must have at least {MinimumPasswordLength} characters.");
            if (security.AdminPassword != security.AdminPassword.Trim())
                errors.Add("Security.AdminPassword must not start or end with whitespace.");
        }
        if (security.DisabledServices.Any(s => s.Equals("api", StringComparison.OrdinalIgnoreCase)))
            errors.Add("Security.DisabledServices must not contain 'api': the library manages the router through it.");
        if (!security.ManageFirewall)
            warnings.Add("Security.ManageFirewall=false: the router keeps its current firewall; make sure the API is not reachable from the site network or LTE.");
    }

    private static HashSet<string> ValidateInterfaces(MikrotikConfigurationPackage package, List<string> errors)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(package.Wan.Interface))
            errors.Add("Wan.Interface is required.");
        else
            names.Add(package.Wan.Interface);
        if (string.IsNullOrWhiteSpace(package.Lan.BridgeName))
            errors.Add("Lan.BridgeName is required.");
        if (package.Lan.Ports.Count == 0)
            errors.Add("Lan.Ports must contain at least one port.");
        foreach (var port in package.Lan.Ports)
        {
            if (string.IsNullOrWhiteSpace(port))
                errors.Add("Lan.Ports contains an empty name.");
            else if (port == package.Wan.Interface)
                errors.Add($"Lan.Ports must not contain the WAN interface {port}.");
            else if (package.Lte.Enabled && port == package.Lte.Interface)
                errors.Add($"Lan.Ports must not contain the LTE interface {port}.");
            else if (!names.Add(port))
                errors.Add($"Lan.Ports lists {port} twice.");
        }
        if (package.Lte.Enabled && package.Lte.Interface == package.Wan.Interface)
            errors.Add("Lte.Interface must differ from Wan.Interface.");
        return names;
    }

    private static Ipv4Prefix? ValidateLan(LanSettings lan, List<string> errors, List<string> warnings, out IPAddress? poolStart, out IPAddress? poolEnd)
    {
        poolStart = poolEnd = null;
        if (!Ipv4Prefix.TryParse(lan.Address, out var prefix) || !lan.Address.Contains('/'))
        {
            errors.Add($"Lan.Address '{lan.Address}' must be an IPv4 address with prefix, e.g. 10.64.12.1/24.");
            return null;
        }
        if (prefix.PrefixLength is < 16 or > 29)
            errors.Add("Lan.Address prefix must be between /16 and /29.");
        if (prefix.IsNetworkOrBroadcastAddress)
            errors.Add($"Lan.Address {prefix.Address} is the network or broadcast address of {prefix.NetworkCidr}.");
        if (prefix.PrefixLength is >= 16 and <= 29 && !prefix.IsNetworkOrBroadcastAddress && lan.Dhcp.Enabled)
        {
            try
            {
                (poolStart, poolEnd) = ResolvePool(lan.Dhcp, prefix);
                var start = Ipv4Prefix.ToUInt(poolStart);
                var end = Ipv4Prefix.ToUInt(poolEnd);
                if (!prefix.Contains(poolStart) || !prefix.Contains(poolEnd))
                    errors.Add($"Lan.Dhcp pool {poolStart}-{poolEnd} must be inside {prefix.NetworkCidr}.");
                else if (start > end)
                    errors.Add($"Lan.Dhcp.PoolStart {poolStart} is after PoolEnd {poolEnd}.");
                else if (start <= Ipv4Prefix.ToUInt(prefix.Network) || end >= Ipv4Prefix.ToUInt(prefix.Broadcast))
                    errors.Add("Lan.Dhcp pool must not include the network or broadcast address.");
                var router = Ipv4Prefix.ToUInt(prefix.Address);
                if (router >= start && router <= end)
                    errors.Add($"Lan.Dhcp pool {poolStart}-{poolEnd} must not include the router address {prefix.Address}.");
            }
            catch (FormatException e)
            {
                errors.Add(e.Message);
            }
        }
        if (lan.Dhcp.LeaseTimeHours is < 1 or > 24 * 30)
            errors.Add("Lan.Dhcp.LeaseTimeHours must be between 1 and 720.");

        var macs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ips = new HashSet<string>(StringComparer.Ordinal);
        foreach (var lease in lan.Dhcp.StaticLeases)
        {
            string mac;
            try
            {
                mac = Discovery.MikrotikNeighbor.FormatMac(Discovery.LinkLocal.ParseMac(lease.MacAddress));
            }
            catch (FormatException)
            {
                errors.Add($"Static lease MAC '{lease.MacAddress}' is invalid.");
                continue;
            }
            if (!macs.Add(mac))
                errors.Add($"Static lease MAC {mac} is listed twice.");
            if (!Ipv4Prefix.TryParseAddress(lease.Address, out var ip) || !prefix.Contains(ip))
                errors.Add($"Static lease address '{lease.Address}' ({mac}) must be inside {prefix.NetworkCidr}.");
            else if (ip.Equals(prefix.Address) || new Ipv4Prefix(ip, prefix.PrefixLength).IsNetworkOrBroadcastAddress)
                errors.Add($"Static lease address {ip} ({mac}) is the router, network or broadcast address.");
            else if (!ips.Add(ip.ToString()))
                errors.Add($"Static lease address {ip} is used twice.");
            else if (poolStart != null && poolEnd != null
                     && Ipv4Prefix.ToUInt(ip) >= Ipv4Prefix.ToUInt(poolStart) && Ipv4Prefix.ToUInt(ip) <= Ipv4Prefix.ToUInt(poolEnd))
                warnings.Add($"Static lease {ip} ({mac}) is inside the dynamic pool; prefer addresses outside {poolStart}-{poolEnd}.");
        }

        if (prefix.NetworkCidr == "192.168.88.0/24")
            warnings.Add("Lan.Address uses the MikroTik factory subnet 192.168.88.0/24. Use a unique subnet per parking when LAN devices must be reachable over the VPN.");
        return prefix;
    }

    private static void ValidateDns(MikrotikConfigurationPackage package, List<string> errors)
    {
        if (package.Dns.Servers.Count == 0)
            errors.Add("Dns.Servers must contain at least one server.");
        foreach (var server in package.Dns.Servers)
            if (!Ipv4Prefix.TryParseAddress(server, out _))
                errors.Add($"DNS server '{server}' is not an IPv4 address.");
        foreach (var ntp in package.Time.NtpServers)
            if (string.IsNullOrWhiteSpace(ntp) || ntp.Contains(' '))
                errors.Add($"NTP server '{ntp}' is invalid.");
    }

    private static void ValidateFailover(MikrotikConfigurationPackage package, Ipv4Prefix? lan, List<string> errors)
    {
        var failover = package.Failover;
        if (!failover.Enabled)
            return;
        if (failover.CheckHosts.Count is < 1 or > 4)
            errors.Add("Failover.CheckHosts must contain 1-4 public IPv4 addresses.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var host in failover.CheckHosts)
        {
            if (!Ipv4Prefix.TryParseAddress(host, out var ip))
            {
                errors.Add($"Failover check host '{host}' is not an IPv4 address.");
                continue;
            }
            if (!seen.Add(ip.ToString()))
                errors.Add($"Failover check host {ip} is listed twice.");
            if (package.Dns.Servers.Contains(ip.ToString()))
                errors.Add($"Failover check host {ip} is also a DNS server: traffic to it is pinned to the primary link, so DNS would fail during failover. Use different addresses.");
            if (lan != null && lan.Contains(ip))
                errors.Add($"Failover check host {ip} is inside the LAN {lan.NetworkCidr}.");
            if (IsPrivate(ip))
                errors.Add($"Failover check host {ip} is a private address; use public hosts (e.g. 1.0.0.1, 208.67.222.222) to detect a dead uplink.");
        }
        if (package.Lte.Enabled && package.Lte.RouteDistance <= failover.CheckHosts.Count)
            errors.Add($"Lte.RouteDistance ({package.Lte.RouteDistance}) must be greater than the number of failover check hosts ({failover.CheckHosts.Count}).");
    }

    private static void ValidateLte(LteSettings lte, Ipv4Prefix? lan, List<string> errors)
    {
        if (!lte.Enabled)
            return;
        if (string.IsNullOrWhiteSpace(lte.Interface))
            errors.Add("Lte.Interface is required.");
        if (lte.RouteDistance is < 2 or > 254)
            errors.Add("Lte.RouteDistance must be between 2 and 254.");
        if (lte.Mode == LteMode.Modem && string.IsNullOrWhiteSpace(lte.Apn))
            errors.Add("Lte.Apn is required in Modem mode.");
        if (lte.Pin != null && (lte.Pin.Length is < 4 or > 8 || !lte.Pin.All(char.IsDigit)))
            errors.Add("Lte.Pin must be 4-8 digits.");
        if (lte.Mode == LteMode.HiLink)
        {
            if (!Ipv4Prefix.TryParse(lte.HiLinkNetwork, out var hiLink))
                errors.Add($"Lte.HiLinkNetwork '{lte.HiLinkNetwork}' is not a CIDR network.");
            else if (lan != null && lan.Overlaps(hiLink))
                errors.Add($"Lan.Address {lan.NetworkCidr} overlaps the HiLink modem network {hiLink.NetworkCidr}.");
        }
    }

    private static void ValidateVpn(MikrotikConfigurationPackage package, Ipv4Prefix? lan, List<string> errors, List<string> warnings)
    {
        var vpn = package.Vpn;
        if (!vpn.Enabled)
            return;
        if (string.IsNullOrWhiteSpace(vpn.InterfaceName))
            errors.Add("Vpn.InterfaceName is required.");
        if (!Ipv4Prefix.TryParse(vpn.Address, out var address) || vpn.Address?.Contains('/') != true)
        {
            errors.Add($"Vpn.Address '{vpn.Address}' must be the tunnel address with the VPN prefix, e.g. 10.250.0.12/16.");
            address = null;
        }
        else if (address.IsNetworkOrBroadcastAddress)
        {
            errors.Add($"Vpn.Address {address.Address} is the network or broadcast address.");
        }
        if (!WireGuardKeys.IsValidKey(vpn.ServerPublicKey))
            errors.Add("Vpn.ServerPublicKey must be a base64 WireGuard key (44 characters).");
        if (vpn.PrivateKey != null && !WireGuardKeys.IsValidKey(vpn.PrivateKey))
            errors.Add("Vpn.PrivateKey must be a base64 WireGuard key or null (generated on the router).");
        if (vpn.PresharedKey != null && !WireGuardKeys.IsValidKey(vpn.PresharedKey))
            errors.Add("Vpn.PresharedKey must be a base64 WireGuard key or null.");
        if (string.IsNullOrWhiteSpace(vpn.ServerEndpoint) || vpn.ServerEndpoint.Contains(' ') || vpn.ServerEndpoint.Contains(':'))
            errors.Add("Vpn.ServerEndpoint must be a host name or IPv4 address without port (set Vpn.ServerPort).");
        if (vpn.ServerPort is < 1 or > 65535 || vpn.ListenPort is < 1 or > 65535)
            errors.Add("Vpn.ServerPort and Vpn.ListenPort must be 1-65535.");
        if (vpn.Mtu is < 1280 or > 1500)
            errors.Add("Vpn.Mtu must be 1280-1500 (1420 is standard; use 1380 if LTE links fragment).");
        if (vpn.PersistentKeepaliveSeconds is < 0 or > 3600)
            errors.Add("Vpn.PersistentKeepaliveSeconds must be 0-3600.");
        if (vpn.PersistentKeepaliveSeconds == 0)
            warnings.Add("Vpn.PersistentKeepaliveSeconds=0: behind NAT (site network, LTE) the hub cannot reach the router until it sends traffic itself.");
        if (vpn.Watchdog && vpn.WatchdogHandshakeTimeoutSeconds < 150)
            errors.Add("Vpn.WatchdogHandshakeTimeoutSeconds must be at least 150 (WireGuard re-handshakes every 2 minutes).");

        var networks = new List<Ipv4Prefix>();
        foreach (var allowed in vpn.AllowedAddresses)
        {
            if (!Ipv4Prefix.TryParse(allowed, out var network) || !allowed.Contains('/'))
                errors.Add($"Vpn.AllowedAddresses entry '{allowed}' must be a CIDR network.");
            else
                networks.Add(network);
        }
        if (address != null && networks.Count == 0)
            networks.Add(address);
        if (address != null && networks.Count > 0 && !networks.Any(n => new Ipv4Prefix(n.Network, n.PrefixLength).Contains(address.Address)))
            warnings.Add($"Vpn.AllowedAddresses do not include the tunnel address {address.Address}; the hub's tunnel IP must be inside them.");
        if (lan != null)
        {
            foreach (var network in networks)
                if (network.Overlaps(lan))
                    errors.Add($"VPN network {network.NetworkCidr} overlaps the LAN {lan.NetworkCidr}.");
        }
        if (networks.Any(n => n.PrefixLength == 0))
            errors.Add("Vpn.AllowedAddresses must not contain 0.0.0.0/0: internet traffic stays on the local uplinks.");
    }

    internal static (IPAddress Start, IPAddress End) ResolvePool(DhcpServerSettings dhcp, Ipv4Prefix lan)
    {
        var network = Ipv4Prefix.ToUInt(lan.Network);
        var broadcast = Ipv4Prefix.ToUInt(lan.Broadcast);
        var router = Ipv4Prefix.ToUInt(lan.Address);

        IPAddress start, end;
        if (dhcp.PoolStart != null)
            start = Ipv4Prefix.TryParseAddress(dhcp.PoolStart, out var s) ? s : throw new FormatException($"Lan.Dhcp.PoolStart '{dhcp.PoolStart}' is not an IPv4 address.");
        else if (lan.Size >= 256)
            start = Ipv4Prefix.FromUInt(network + 100 == router ? network + 101 : network + 100);
        else
            start = Ipv4Prefix.FromUInt(router == network + 1 ? network + 2 : network + 1);

        if (dhcp.PoolEnd != null)
            end = Ipv4Prefix.TryParseAddress(dhcp.PoolEnd, out var e) ? e : throw new FormatException($"Lan.Dhcp.PoolEnd '{dhcp.PoolEnd}' is not an IPv4 address.");
        else if (lan.Size >= 256)
            end = Ipv4Prefix.FromUInt(network + 250 == router ? network + 249 : Math.Min(network + 250, broadcast - 1));
        else
            end = Ipv4Prefix.FromUInt(router == broadcast - 1 ? broadcast - 2 : broadcast - 1);

        // For small subnets the default range must skip the router when it sits in the middle.
        var su = Ipv4Prefix.ToUInt(start);
        var eu = Ipv4Prefix.ToUInt(end);
        if (dhcp.PoolStart == null && dhcp.PoolEnd == null && router >= su && router <= eu)
        {
            if (router - su >= eu - router)
                end = Ipv4Prefix.FromUInt(router - 1);
            else
                start = Ipv4Prefix.FromUInt(router + 1);
        }
        return (start, end);
    }

    private static bool IsPrivate(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)
               || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || (b[0] == 169 && b[1] == 254);
    }
}
