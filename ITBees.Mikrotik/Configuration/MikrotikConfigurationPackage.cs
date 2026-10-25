using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ITBees.Mikrotik.Configuration;

/// <summary>
/// Complete desired state of a parking router. Apply it with <see cref="Provisioning.MikrotikProvisioner"/>;
/// applying the same package again changes nothing, so it can be re-sent at any time (e.g. from the
/// Octopark admin panel). Defaults describe the standard parking setup on an RB960PGS (hEX PoE):
/// ether1 = primary internet from the site LAN (DHCP), Huawei E3372 on USB = LTE backup,
/// ether2-ether5 + sfp1 = parking device LAN, WireGuard tunnel to the central VPN hub.
/// With <see cref="LanMode.SharedSiteNetwork"/> the parking devices stay on the site network instead and use
/// the router (its LAN address on ether1) as their gateway.
/// </summary>
public sealed class MikrotikConfigurationPackage
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    /// <summary>Router name (/system identity), e.g. "octopark-krakow-p12". Null keeps the current name.</summary>
    public string? Identity { get; set; }

    public SecuritySettings Security { get; set; } = new();

    public WanSettings Wan { get; set; } = new();

    public LteSettings Lte { get; set; } = new();

    public FailoverSettings Failover { get; set; } = new();

    public LanSettings Lan { get; set; } = new();

    public DnsSettings Dns { get; set; } = new();

    public TimeSettings Time { get; set; } = new();

    public VpnSettings Vpn { get; set; } = new();

    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        // Packages are edited by people and stored in the admin panel: keep "<", "ł", "ą" readable.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static MikrotikConfigurationPackage FromJson(string json) =>
        JsonSerializer.Deserialize<MikrotikConfigurationPackage>(json, JsonOptions)
        ?? throw new MikrotikConfigurationException(new[] { "The JSON document is empty." });

    /// <summary>Checks the package without contacting a router.</summary>
    public MikrotikValidationResult Validate() => MikrotikConfigurationValidator.Validate(this);
}

public sealed class SecuritySettings
{
    /// <summary>
    /// New password for the user the library is logged in as (normally "admin"). Replaces the factory
    /// password from the sticker. Store it in the Octopark admin panel or use one standard parking password.
    /// </summary>
    public string? AdminPassword { get; set; }

    /// <summary>Must be true to apply a package without <see cref="AdminPassword"/> (keeps the current password).</summary>
    public bool KeepCurrentPassword { get; set; }

    /// <summary>Services switched off. The API service is always kept (the library needs it).</summary>
    public List<string> DisabledServices { get; set; } = new() { "telnet", "ftp", "www", "www-ssl", "api-ssl" };

    /// <summary>Neighbor discovery, MAC-Telnet and MAC-Winbox only on the LAN list (never on the site network on ether1).</summary>
    public bool RestrictDiscoveryToLan { get; set; } = true;

    /// <summary>Install the library's firewall (input/forward, IPv4 and IPv6) at the top of the filter tables.</summary>
    public bool ManageFirewall { get; set; } = true;

    /// <summary>Remove factory rules commented "defconf" (they are superseded by the managed firewall).</summary>
    public bool RemoveDefconfFirewall { get; set; } = true;
}

public sealed class WanSettings
{
    /// <summary>Primary uplink port, connected to the site network that provides internet.</summary>
    public string Interface { get; set; } = "ether1";

    /// <summary>Use DNS servers from the site DHCP. Off by default: they often stop working when the site link fails.</summary>
    public bool UsePeerDns { get; set; }

    /// <summary>Remove static IPv4 addresses from the WAN port (it must work as a DHCP client).</summary>
    public bool RemoveStaticAddresses { get; set; } = true;

    /// <summary>How long to wait for the DHCP lease from the site network during apply (0 = do not wait).</summary>
    public int WaitForLeaseSeconds { get; set; } = 20;
}

public enum LteMode
{
    /// <summary>
    /// Huawei E3372h with HiLink firmware (the common retail version): the stick is a small router with its own
    /// NAT and DHCP (192.168.8.0/24). RouterOS shows it as lte1 and gets an address with a DHCP client.
    /// APN and PIN are set in the stick's web panel (http://192.168.8.1).
    /// </summary>
    HiLink,

    /// <summary>Modem driven by RouterOS (/interface lte with an APN profile), e.g. E3372s stick firmware or MikroTik LTE cards.</summary>
    Modem,
}

public sealed class LteSettings
{
    public bool Enabled { get; set; } = true;

    public string Interface { get; set; } = "lte1";

    public LteMode Mode { get; set; } = LteMode.HiLink;

    /// <summary>APN for <see cref="LteMode.Modem"/> (e.g. "internet").</summary>
    public string? Apn { get; set; }

    /// <summary>SIM PIN for <see cref="LteMode.Modem"/>. In HiLink mode set it in the stick's web panel.</summary>
    public string? Pin { get; set; }

    /// <summary>Distance of the LTE default route; must be higher than the primary routes (1..n).</summary>
    public int RouteDistance { get; set; } = 10;

    /// <summary>Fail when the modem is not plugged in. Otherwise LTE is skipped with a warning and can be added by re-applying.</summary>
    public bool Required { get; set; }

    /// <summary>Network the HiLink stick uses internally; the parking LAN must not overlap it.</summary>
    public string HiLinkNetwork { get; set; } = "192.168.8.0/24";
}

public sealed class FailoverSettings
{
    /// <summary>
    /// Switch to LTE when the internet behind ether1 stops working (not only when the cable is unplugged)
    /// and back to ether1 when it works again.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Public hosts pinged through ether1 every 10 s (RouterOS check-gateway). The primary link is used while
    /// at least one answers. Traffic to these addresses always goes through ether1, so they must not be the DNS
    /// servers or anything the parking devices depend on.
    /// </summary>
    public List<string> CheckHosts { get; set; } = new() { "1.0.0.1", "208.67.222.222" };

    /// <summary>Drop tracked connections when the uplink changes, so NAT-ed sessions re-establish over the new link at once.</summary>
    public bool FlushConnectionsOnSwitch { get; set; } = true;
}

/// <summary>Where the parking devices are connected.</summary>
public enum LanMode
{
    /// <summary>
    /// Parking devices sit behind the router on its own ports (<see cref="LanSettings.Ports"/>), in their own LAN
    /// with the router's DHCP server. Only the router is connected to the site network (ether1).
    /// </summary>
    OwnPorts,

    /// <summary>
    /// The site network gives no isolation: parking devices stay on the site switches, next to the site's own
    /// devices and DHCP server, and the router is connected to that network with a single cable (ether1). Two
    /// subnets share the wire: the site network (DHCP, the router's uplink) and the parking subnet
    /// (<see cref="LanSettings.Address"/>), whose devices have static addresses and the router as their gateway.
    /// The router puts its LAN address on ether1, runs no DHCP server (it would answer the site's devices), accepts
    /// traffic from ether1 only from the parking subnet and does not send ICMP redirects (they would point devices
    /// at the site router and bypass the failover). <see cref="LanSettings.Ports"/> stay as service ports without
    /// an IPv4 address (reachable over IPv6 link-local). A factory router is applied once from such a port (its
    /// factory address and DHCP live there), which drops that session at the end.
    /// </summary>
    SharedSiteNetwork,
}

public sealed class LanSettings
{
    /// <summary>Own ports behind the router (default) or the parking subnet on the site network, see <see cref="LanMode"/>.</summary>
    public LanMode Mode { get; set; } = LanMode.OwnPorts;

    public string BridgeName { get; set; } = "bridge";

    /// <summary>
    /// Ports in the parking LAN bridge (RB960PGS: ether2-ether5 with PoE out, sfp1). In
    /// <see cref="LanMode.SharedSiteNetwork"/> they are service ports without an IPv4 address.
    /// </summary>
    public List<string> Ports { get; set; } = new() { "ether2", "ether3", "ether4", "ether5", "sfp1" };

    /// <summary>
    /// Router address with prefix, e.g. "10.64.12.1/24". Use a different subnet for each parking when devices
    /// behind the router must be reachable over the VPN. Applied as the very last step, because it changes the
    /// address a computer on the LAN uses to reach the router. In <see cref="LanMode.SharedSiteNetwork"/> it is set
    /// on the WAN port and must not overlap the site network.
    /// </summary>
    public string Address { get; set; } = "192.168.88.1/24";

    public DhcpServerSettings Dhcp { get; set; } = new();

    /// <summary>Static DNS name of the router for LAN devices; null to skip.</summary>
    public string? RouterDnsName { get; set; } = "router.lan";
}

public sealed class DhcpServerSettings
{
    /// <summary>Must be false in <see cref="LanMode.SharedSiteNetwork"/>: the site network already has a DHCP server.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>First pool address; default .100 (or the address after the router for small subnets).</summary>
    public string? PoolStart { get; set; }

    /// <summary>Last pool address; default .250 in a /24.</summary>
    public string? PoolEnd { get; set; }

    public int LeaseTimeHours { get; set; } = 24;

    /// <summary>Fixed addresses for parking devices (barriers, cameras, terminals, I/O modules).</summary>
    public List<StaticLease> StaticLeases { get; set; } = new();
}

public sealed class StaticLease
{
    public string MacAddress { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    /// <summary>Description shown in Winbox, e.g. "barrier entry".</summary>
    public string? Comment { get; set; }
}

public sealed class DnsSettings
{
    public List<string> Servers { get; set; } = new() { "1.1.1.1", "8.8.8.8" };

    /// <summary>Router answers DNS for the LAN (DHCP hands out the router as DNS). WAN access is blocked by the firewall.</summary>
    public bool AllowRemoteRequests { get; set; } = true;
}

public sealed class TimeSettings
{
    public string? TimeZone { get; set; } = "Europe/Warsaw";

    public List<string> NtpServers { get; set; } = new() { "0.pl.pool.ntp.org", "1.pl.pool.ntp.org" };
}

/// <summary>WireGuard tunnel from the router to the central VPN hub (RouterOS 7).</summary>
public sealed class VpnSettings
{
    public bool Enabled { get; set; }

    public string InterfaceName { get; set; } = "wg-octopark";

    /// <summary>
    /// Router private key. Null: the router generates one and it never leaves the device (the public key is
    /// returned in the result). Set it to register the peer on the hub before installation
    /// (<see cref="WireGuard.WireGuardKeys.GenerateKeyPair"/>).
    /// </summary>
    public string? PrivateKey { get; set; }

    public int ListenPort { get; set; } = 13231;

    public int Mtu { get; set; } = 1420;

    /// <summary>Tunnel address of this router with the VPN network prefix, e.g. "10.250.0.12/16".</summary>
    public string? Address { get; set; }

    public string? ServerPublicKey { get; set; }

    /// <summary>Hub address: a static public IP or a DNS name (re-resolved by the watchdog).</summary>
    public string? ServerEndpoint { get; set; }

    public int ServerPort { get; set; } = 51820;

    public string? PresharedKey { get; set; }

    /// <summary>Networks reached through the tunnel. Empty = the VPN network of <see cref="Address"/>.</summary>
    public List<string> AllowedAddresses { get; set; } = new();

    /// <summary>Keeps NAT mappings open (site NAT and LTE carrier NAT) so the hub can always reach the router.</summary>
    public int PersistentKeepaliveSeconds { get; set; } = 25;

    /// <summary>Allow Winbox/API/SSH/ping to the router from the VPN.</summary>
    public bool AllowManagement { get; set; } = true;

    /// <summary>Allow the VPN to reach parking devices on the LAN (the hub must route the LAN subnet to this peer).</summary>
    public bool AllowAccessToLan { get; set; } = true;

    /// <summary>Allow parking devices to reach VPN networks (e.g. a central Octopark server).</summary>
    public bool AllowLanToVpn { get; set; } = true;

    /// <summary>
    /// Script run every minute that forces a new handshake (and DNS re-resolution) when the tunnel goes quiet.
    /// The scheduler runs it, or netwatch when the router's device-mode blocks the scheduler.
    /// </summary>
    public bool Watchdog { get; set; } = true;

    public int WatchdogHandshakeTimeoutSeconds { get; set; } = 180;
}
