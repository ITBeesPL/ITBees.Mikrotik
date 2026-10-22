using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace ITBees.Mikrotik.Discovery;

/// <summary>
/// MikroTik Neighbor Discovery Protocol packet (UDP 5678), the protocol Winbox uses to list routers.
/// Layout: 2 bytes header, 2 bytes sequence number (big-endian), then TLVs:
/// type (2 bytes BE), length (2 bytes BE, value only), value.
/// </summary>
public sealed class MndpPacket
{
    public const int Port = 5678;

    public const ushort TlvMacAddress = 1;
    public const ushort TlvIdentity = 5;
    public const ushort TlvVersion = 7;
    public const ushort TlvPlatform = 8;
    public const ushort TlvUptime = 10;
    public const ushort TlvSoftwareId = 11;
    public const ushort TlvBoard = 12;
    public const ushort TlvUnpack = 14;
    public const ushort TlvIpv6Address = 15;
    public const ushort TlvInterfaceName = 16;
    public const ushort TlvIpv4Address = 17;

    /// <summary>The discovery request Winbox sends: four zero bytes. Routers answer with their MNDP packet.</summary>
    public static ReadOnlyMemory<byte> DiscoveryRequest { get; } = new byte[4];

    public ushort SequenceNumber { get; init; }

    public PhysicalAddress? MacAddress { get; init; }

    public string? Identity { get; init; }

    public string? Version { get; init; }

    public string? Platform { get; init; }

    public TimeSpan? Uptime { get; init; }

    public string? SoftwareId { get; init; }

    public string? Board { get; init; }

    public IPAddress? Ipv6Address { get; init; }

    /// <summary>Router interface the packet was sent from (e.g. "bridge").</summary>
    public string? InterfaceName { get; init; }

    public IPAddress? Ipv4Address { get; init; }

    /// <summary>All TLVs including unknown ones, for diagnostics.</summary>
    public IReadOnlyDictionary<ushort, byte[]> Tlvs { get; init; } = new Dictionary<ushort, byte[]>();

    /// <summary>Parses a datagram. Returns false for the 4-byte request and anything without a MAC address.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out MndpPacket? packet)
    {
        packet = null;
        if (data.Length < 4 + 4)
            return false;

        var tlvs = new Dictionary<ushort, byte[]>();
        var offset = 4;
        while (offset + 4 <= data.Length)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 2)..]);
            offset += 4;
            if (offset + length > data.Length)
                return false;
            tlvs[type] = data.Slice(offset, length).ToArray();
            offset += length;
        }

        if (!tlvs.TryGetValue(TlvMacAddress, out var mac) || mac.Length != 6)
            return false;

        packet = new MndpPacket
        {
            SequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(data[2..]),
            MacAddress = new PhysicalAddress(mac),
            Identity = GetString(tlvs, TlvIdentity),
            Version = GetString(tlvs, TlvVersion),
            Platform = GetString(tlvs, TlvPlatform),
            Uptime = tlvs.TryGetValue(TlvUptime, out var uptime) && uptime.Length == 4
                ? TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32LittleEndian(uptime))
                : null,
            SoftwareId = GetString(tlvs, TlvSoftwareId),
            Board = GetString(tlvs, TlvBoard),
            Ipv6Address = tlvs.TryGetValue(TlvIpv6Address, out var v6) && v6.Length == 16 ? new IPAddress(v6) : null,
            InterfaceName = GetString(tlvs, TlvInterfaceName),
            Ipv4Address = tlvs.TryGetValue(TlvIpv4Address, out var v4) && v4.Length == 4 ? new IPAddress(v4) : null,
            Tlvs = tlvs,
        };
        return true;
    }

    /// <summary>Serialises the packet (used by tests and emulators).</summary>
    public byte[] ToBytes()
    {
        using var buffer = new MemoryStream();
        Span<byte> header = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], SequenceNumber);
        buffer.Write(header);
        if (MacAddress != null)
            WriteTlv(buffer, TlvMacAddress, MacAddress.GetAddressBytes());
        WriteString(buffer, TlvIdentity, Identity);
        WriteString(buffer, TlvVersion, Version);
        WriteString(buffer, TlvPlatform, Platform);
        if (Uptime != null)
        {
            var uptime = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(uptime, (uint)Uptime.Value.TotalSeconds);
            WriteTlv(buffer, TlvUptime, uptime);
        }
        WriteString(buffer, TlvSoftwareId, SoftwareId);
        WriteString(buffer, TlvBoard, Board);
        if (Ipv6Address != null)
            WriteTlv(buffer, TlvIpv6Address, Ipv6Address.GetAddressBytes());
        WriteString(buffer, TlvInterfaceName, InterfaceName);
        if (Ipv4Address != null)
            WriteTlv(buffer, TlvIpv4Address, Ipv4Address.GetAddressBytes());
        return buffer.ToArray();
    }

    private static string? GetString(Dictionary<ushort, byte[]> tlvs, ushort type) =>
        tlvs.TryGetValue(type, out var value) ? Encoding.UTF8.GetString(value).TrimEnd('\0') : null;

    private static void WriteString(Stream stream, ushort type, string? value)
    {
        if (value != null)
            WriteTlv(stream, type, Encoding.UTF8.GetBytes(value));
    }

    private static void WriteTlv(Stream stream, ushort type, byte[] value)
    {
        Span<byte> header = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(header, type);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], (ushort)value.Length);
        stream.Write(header);
        stream.Write(value);
    }
}
