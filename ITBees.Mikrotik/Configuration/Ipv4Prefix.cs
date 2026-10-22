using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ITBees.Mikrotik.Configuration;

/// <summary>An IPv4 address with prefix length, e.g. "10.64.12.1/24" (interface address) or "10.250.0.0/16" (network).</summary>
public sealed record Ipv4Prefix(IPAddress Address, int PrefixLength)
{
    public uint Mask => PrefixLength == 0 ? 0u : uint.MaxValue << (32 - PrefixLength);

    public IPAddress Network => FromUInt(ToUInt(Address) & Mask);

    public IPAddress Broadcast => FromUInt((ToUInt(Address) & Mask) | ~Mask);

    /// <summary>Network in CIDR notation, e.g. "10.64.12.0/24".</summary>
    public string NetworkCidr => $"{Network}/{PrefixLength}";

    /// <summary>True when the address is the network or broadcast address of its subnet (prefixes below /31).</summary>
    public bool IsNetworkOrBroadcastAddress =>
        PrefixLength < 31 && (Address.Equals(Network) || Address.Equals(Broadcast));

    public static bool TryParse(string? text, out Ipv4Prefix prefix)
    {
        prefix = new Ipv4Prefix(IPAddress.Any, 0);
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var parts = text.Trim().Split('/');
        if (parts.Length > 2 || !TryParseAddress(parts[0], out var address))
            return false;
        var length = 32;
        if (parts.Length == 2 && (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out length) || length is < 0 or > 32))
            return false;
        prefix = new Ipv4Prefix(address, length);
        return true;
    }

    public static Ipv4Prefix Parse(string text) =>
        TryParse(text, out var prefix) ? prefix : throw new FormatException($"'{text}' is not an IPv4 address or CIDR prefix.");

    /// <summary>Strict dotted-quad parsing (IPAddress.TryParse also accepts "10" or "10.1").</summary>
    public static bool TryParseAddress(string? text, out IPAddress address)
    {
        address = IPAddress.Any;
        if (string.IsNullOrWhiteSpace(text) || text.Count(c => c == '.') != 3)
            return false;
        if (!IPAddress.TryParse(text.Trim(), out var parsed) || parsed.AddressFamily != AddressFamily.InterNetwork)
            return false;
        address = parsed;
        return true;
    }

    public bool Contains(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork && (ToUInt(address) & Mask) == (ToUInt(Address) & Mask);

    public bool Overlaps(Ipv4Prefix other)
    {
        var shorter = Math.Min(PrefixLength, other.PrefixLength);
        var mask = shorter == 0 ? 0u : uint.MaxValue << (32 - shorter);
        return (ToUInt(Address) & mask) == (ToUInt(other.Address) & mask);
    }

    /// <summary>The n-th address of the subnet (0 = network address).</summary>
    public IPAddress HostAt(uint offset) => FromUInt((ToUInt(Address) & Mask) + offset);

    public uint Size => PrefixLength == 0 ? uint.MaxValue : 1u << (32 - PrefixLength);

    public override string ToString() => $"{Address}/{PrefixLength}";

    public static uint ToUInt(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return (uint)b[0] << 24 | (uint)b[1] << 16 | (uint)b[2] << 8 | b[3];
    }

    public static IPAddress FromUInt(uint value) =>
        new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

    public static bool SameNetwork(IPAddress a, IPAddress b, int prefixLength) =>
        new Ipv4Prefix(a, prefixLength).Contains(b);

    public static IPAddress BroadcastOf(IPAddress address, int prefixLength) =>
        new Ipv4Prefix(address, prefixLength).Broadcast;
}
