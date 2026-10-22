using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ITBees.Mikrotik.Discovery;

/// <summary>A router found by MNDP discovery.</summary>
public sealed record MikrotikNeighbor
{
    /// <summary>MAC address of the router interface facing us (the "MAC" column in Winbox).</summary>
    public required PhysicalAddress MacAddress { get; init; }

    public string? Identity { get; init; }

    /// <summary>RouterOS version, e.g. "7.16.2 (stable)".</summary>
    public string? Version { get; init; }

    public string? Platform { get; init; }

    /// <summary>Board name, e.g. "hEX PoE" for RB960PGS.</summary>
    public string? Board { get; init; }

    public string? SoftwareId { get; init; }

    public TimeSpan? Uptime { get; init; }

    /// <summary>Router interface that sent the announcement (usually "bridge").</summary>
    public string? RouterInterface { get; init; }

    /// <summary>IPv4 address of that router interface (may be in a different subnet than this computer).</summary>
    public IPAddress? Ipv4Address { get; init; }

    /// <summary>IPv6 address announced by the router, if any.</summary>
    public IPAddress? Ipv6Address { get; init; }

    /// <summary>Source address of the received datagram.</summary>
    public IPAddress? SourceAddress { get; init; }

    /// <summary>Index of the local network interface the announcement arrived on (IPv6 scope id); 0 when unknown.</summary>
    public int LocalInterfaceIndex { get; init; }

    public string? LocalInterfaceName { get; init; }

    public DateTimeOffset LastSeen { get; init; }

    /// <summary>MAC as printed by RouterOS: "4C:5E:0C:11:22:33".</summary>
    public string MacAddressText => FormatMac(MacAddress);

    /// <summary>
    /// IPv6 link-local address of the router on our segment: the announced one when it is link-local,
    /// otherwise derived from the MAC (EUI-64). Carries the local scope id, so it is reachable even when
    /// the router's IPv4 address belongs to another subnet (requires IPv6, enabled by default in RouterOS 7).
    /// </summary>
    public IPAddress? LinkLocalAddress
    {
        get
        {
            var address = Ipv6Address is { IsIPv6LinkLocal: true }
                ? new IPAddress(Ipv6Address.GetAddressBytes())
                : LinkLocal.FromMac(MacAddress);
            if (LocalInterfaceIndex > 0)
                address.ScopeId = LocalInterfaceIndex;
            else if (SourceAddress is { IsIPv6LinkLocal: true } source && source.ScopeId > 0)
                address.ScopeId = source.ScopeId;
            return address.ScopeId > 0 ? address : null;
        }
    }

    /// <summary>
    /// Addresses worth trying for an API connection, best first: IPv4 when it is in one of our subnets,
    /// then the IPv6 link-local address (works across IPv4 subnets), then the remaining addresses.
    /// </summary>
    public IReadOnlyList<IPAddress> GetConnectionCandidates()
    {
        var candidates = new List<IPAddress>();
        var ipv4Reachable = Ipv4Address != null && !Ipv4Address.Equals(IPAddress.Any) && LocalSubnets.IsOnLink(Ipv4Address);
        if (ipv4Reachable)
            candidates.Add(Ipv4Address!);
        if (LinkLocalAddress is { } linkLocal)
            candidates.Add(linkLocal);
        if (!ipv4Reachable && Ipv4Address != null && !Ipv4Address.Equals(IPAddress.Any))
            candidates.Add(Ipv4Address);
        if (SourceAddress is { AddressFamily: AddressFamily.InterNetwork } source && !candidates.Contains(source))
            candidates.Add(source);
        if (Ipv6Address is { IsIPv6LinkLocal: false } global && !candidates.Contains(global))
            candidates.Add(global);
        return candidates;
    }

    public override string ToString() =>
        $"{MacAddressText} {Identity ?? "?"} {Board ?? "?"} RouterOS {Version ?? "?"} IPv4 {Ipv4Address?.ToString() ?? "-"} via {LocalInterfaceName ?? "?"}";

    internal static string FormatMac(PhysicalAddress mac) => string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));
}

/// <summary>IPv6 link-local helpers.</summary>
public static class LinkLocal
{
    /// <summary>fe80::/64 address built from a MAC with modified EUI-64 (RFC 4291), as RouterOS assigns it.</summary>
    public static IPAddress FromMac(PhysicalAddress mac)
    {
        var m = mac.GetAddressBytes();
        if (m.Length != 6)
            throw new ArgumentException("A 48-bit MAC address is required.", nameof(mac));
        var bytes = new byte[16];
        bytes[0] = 0xFE;
        bytes[1] = 0x80;
        bytes[8] = (byte)(m[0] ^ 0x02);
        bytes[9] = m[1];
        bytes[10] = m[2];
        bytes[11] = 0xFF;
        bytes[12] = 0xFE;
        bytes[13] = m[3];
        bytes[14] = m[4];
        bytes[15] = m[5];
        return new IPAddress(bytes);
    }

    /// <summary>Parses "4C:5E:0C:11:22:33", "4c-5e-0c-11-22-33" or "4C5E0C112233".</summary>
    public static PhysicalAddress ParseMac(string mac)
    {
        var hex = new string(mac.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12)
            throw new FormatException($"'{mac}' is not a MAC address.");
        return new PhysicalAddress(Convert.FromHexString(hex));
    }
}

/// <summary>IPv4 subnets configured on this computer.</summary>
internal static class LocalSubnets
{
    public static bool IsOnLink(IPAddress address)
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;
                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork || unicast.PrefixLength is <= 0 or > 32)
                        continue;
                    if (Configuration.Ipv4Prefix.SameNetwork(unicast.Address, address, unicast.PrefixLength))
                        return true;
                }
            }
        }
        catch (NetworkInformationException)
        {
        }
        return false;
    }

    public static string? InterfaceName(int index)
    {
        if (index <= 0)
            return null;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                var properties = nic.GetIPProperties();
                if (nic.Supports(NetworkInterfaceComponent.IPv4) && properties.GetIPv4Properties()?.Index == index)
                    return nic.Name;
                if (nic.Supports(NetworkInterfaceComponent.IPv6) && properties.GetIPv6Properties()?.Index == index)
                    return nic.Name;
            }
        }
        catch (Exception e) when (e is NetworkInformationException or PlatformNotSupportedException)
        {
        }
        return null;
    }
}
