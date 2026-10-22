using System.Net;
using System.Net.Sockets;
using ITBees.Mikrotik.Discovery;

namespace ITBees.Mikrotik.Tests;

public class DiscoveryTests
{
    private static MndpPacket SamplePacket() => new()
    {
        SequenceNumber = 7,
        MacAddress = LinkLocal.ParseMac("4C:5E:0C:11:22:33"),
        Identity = "MikroTik",
        Version = "7.16.2 (stable)",
        Platform = "MikroTik",
        Uptime = TimeSpan.FromSeconds(3725),
        SoftwareId = "ABCD-1234",
        Board = "hEX PoE",
        InterfaceName = "bridge",
        Ipv4Address = IPAddress.Parse("192.168.88.1"),
        Ipv6Address = IPAddress.Parse("fe80::4e5e:cff:fe11:2233"),
    };

    [Fact]
    public void Packet_RoundTrips()
    {
        var bytes = SamplePacket().ToBytes();
        Assert.True(MndpPacket.TryParse(bytes, out var parsed));
        Assert.Equal("4C5E0C112233", parsed!.MacAddress!.ToString());
        Assert.Equal("MikroTik", parsed.Identity);
        Assert.Equal("7.16.2 (stable)", parsed.Version);
        Assert.Equal("hEX PoE", parsed.Board);
        Assert.Equal("bridge", parsed.InterfaceName);
        Assert.Equal(IPAddress.Parse("192.168.88.1"), parsed.Ipv4Address);
        Assert.Equal(TimeSpan.FromSeconds(3725), parsed.Uptime);
        Assert.Equal(7, parsed.SequenceNumber);
    }

    [Fact]
    public void Packet_UsesBigEndianTlvHeaders()
    {
        var bytes = SamplePacket().ToBytes();
        // header (4) then TLV type 1 (MAC), length 6
        Assert.Equal(new byte[] { 0x00, 0x01, 0x00, 0x06, 0x4C, 0x5E }, bytes.Skip(4).Take(6).ToArray());
    }

    [Fact]
    public void DiscoveryRequest_AndTruncatedPackets_AreIgnored()
    {
        Assert.False(MndpPacket.TryParse(MndpPacket.DiscoveryRequest.Span, out _));
        var bytes = SamplePacket().ToBytes();
        Assert.False(MndpPacket.TryParse(bytes.AsSpan(0, bytes.Length - 2), out _));
    }

    [Fact]
    public void LinkLocal_IsDerivedFromMacWithEui64()
    {
        var address = LinkLocal.FromMac(LinkLocal.ParseMac("4c-5e-0c-11-22-33"));
        Assert.Equal(IPAddress.Parse("fe80::4e5e:cff:fe11:2233"), address);
    }

    [Fact]
    public void Neighbor_PrefersLinkLocalWhenIpv4IsInAnotherSubnet()
    {
        var neighbor = new MikrotikNeighbor
        {
            MacAddress = LinkLocal.ParseMac("4C:5E:0C:11:22:33"),
            Ipv4Address = IPAddress.Parse("203.0.113.77"),
            LocalInterfaceIndex = 5,
        };
        var candidates = neighbor.GetConnectionCandidates();
        Assert.Equal(2, candidates.Count);
        Assert.True(candidates[0].IsIPv6LinkLocal);
        Assert.Equal(5, candidates[0].ScopeId);
        Assert.Equal(IPAddress.Parse("203.0.113.77"), candidates[1]);
    }

    [Fact]
    public async Task Discovery_CollectsAnswers()
    {
        using var responder = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)responder.Client.LocalEndPoint!).Port;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var answering = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var request = await responder.ReceiveAsync(stop.Token);
                    if (request.Buffer.Length == 4)
                        await responder.SendAsync(SamplePacket().ToBytes(), request.RemoteEndPoint, stop.Token);
                }
            }
            catch (OperationCanceledException)
            {
            }
        });

        var discovery = new MndpDiscovery();
        var found = new List<MikrotikNeighbor>();
        discovery.NeighborFound += (_, n) => found.Add(n);
        var neighbors = await discovery.DiscoverAsync(new MndpDiscoveryOptions
        {
            Duration = TimeSpan.FromSeconds(1.5),
            RequestInterval = TimeSpan.FromMilliseconds(300),
            ListenPort = 0,
            TargetPort = port,
            TargetAddresses = new[] { IPAddress.Loopback },
            UseIpv6 = false,
        });
        stop.Cancel();
        await answering;

        var neighbor = Assert.Single(neighbors);
        Assert.Single(found);
        Assert.Equal("4C:5E:0C:11:22:33", neighbor.MacAddressText);
        Assert.Equal("hEX PoE", neighbor.Board);
        Assert.Equal(IPAddress.Parse("192.168.88.1"), neighbor.Ipv4Address);
        Assert.Equal(IPAddress.Loopback, neighbor.SourceAddress);
    }
}
