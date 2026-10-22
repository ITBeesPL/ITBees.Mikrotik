using System.Net;
using System.Net.Sockets;
using ITBees.Mikrotik.Discovery;

namespace ITBees.Mikrotik.Tests;

public class LoginScannerTests
{
    /// <summary>Two routers on the same API port: one on 127.0.0.1, one on ::1 (two addresses on one test machine).</summary>
    private static async Task<(FakeRouterOs A, FakeRouterOs B)> StartPairAsync()
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            var a = FakeRouterOs.StartFactoryRb960(password: "pass-of-A");
            try
            {
                var b = FakeRouterOs.StartFactoryRb960(password: "pass-of-B", address: IPAddress.IPv6Loopback, port: a.Port);
                return (a, b);
            }
            catch (SocketException)
            {
                await a.DisposeAsync();
            }
        }
        throw new InvalidOperationException("No free port for both loopback addresses.");
    }

    private static MikrotikNeighbor Neighbor(string mac, IPAddress? ipv4 = null, IPAddress? ipv6 = null) => new()
    {
        MacAddress = LinkLocal.ParseMac(mac),
        Identity = "MikroTik",
        Ipv4Address = ipv4,
        Ipv6Address = ipv6,
    };

    [Fact]
    public async Task Finds_TheRouterThatAcceptsTheCredentials()
    {
        var (a, b) = await StartPairAsync();
        await using var _ = a;
        await using var __ = b;
        var neighbors = new[]
        {
            Neighbor("4C:5E:0C:00:00:0A", ipv4: IPAddress.Loopback),
            Neighbor("4C:5E:0C:00:00:0B", ipv6: IPAddress.IPv6Loopback),
        };

        var result = await new MikrotikLoginScanner().FindAsync(neighbors, new MikrotikLoginScanOptions
        {
            Credentials = { new MikrotikCredentials("admin", "pass-of-B") },
            Port = a.Port,
        });
        await using var client = result.Client;

        Assert.Equal("4C:5E:0C:00:00:0B", result.Device.MacAddressText);
        Assert.Contains(result.Attempts, x => x.Device.MacAddressText == "4C:5E:0C:00:00:0A" && x.Outcome == MikrotikLoginOutcome.AuthenticationFailed);
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task TriesEveryCredentialPair()
    {
        await using var router = FakeRouterOs.StartFactoryRb960(password: "sticker");
        var result = await new MikrotikLoginScanner().FindAsync(
            new[] { Neighbor("4C:5E:0C:00:00:0A", ipv4: IPAddress.Loopback) },
            new MikrotikLoginScanOptions
            {
                Credentials = { new MikrotikCredentials("admin", "standard-parking"), new MikrotikCredentials("admin", "sticker") },
                Port = router.Port,
            });
        await using var client = result.Client;
        Assert.Equal("sticker", result.Credentials.Password);
    }

    [Fact]
    public async Task ReportsEveryAttempt_WhenNothingMatches()
    {
        await using var router = FakeRouterOs.StartFactoryRb960(password: "sticker");
        var e = await Assert.ThrowsAsync<MikrotikDeviceNotFoundException>(() => new MikrotikLoginScanner().FindAsync(
            new[] { Neighbor("4C:5E:0C:00:00:0A", ipv4: IPAddress.Loopback) },
            new MikrotikLoginScanOptions { Credentials = { new MikrotikCredentials("admin", "wrong") }, Port = router.Port }));

        var attempt = Assert.Single(e.Attempts);
        Assert.Equal(MikrotikLoginOutcome.AuthenticationFailed, attempt.Outcome);
        Assert.Contains("rejected login", e.Message);
    }

    [Fact]
    public async Task EmptyNetwork_GivesAClearError()
    {
        var e = await Assert.ThrowsAsync<MikrotikDeviceNotFoundException>(() => new MikrotikLoginScanner().FindAsync(
            Array.Empty<MikrotikNeighbor>(),
            new MikrotikLoginScanOptions { Credentials = { new MikrotikCredentials("admin", "x") } }));
        Assert.Contains("LAN port", e.Message);
    }
}
