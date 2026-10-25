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
    public async Task KnownMac_FindsTheRouterOnAnotherPort()
    {
        // The label shows ether1 (…:22); the column sits on ether3 and hears that port's MAC (…:24).
        await using var router = FakeRouterOs.StartFactoryRb960(password: "sticker");
        var result = await new MikrotikLoginScanner().FindAsync(
            new[] { Neighbor("4C:5E:0C:11:22:24", ipv4: IPAddress.Loopback) },
            new MikrotikLoginScanOptions
            {
                Credentials = { new MikrotikCredentials("admin", "sticker") },
                KnownMac = "4c-5e-0c-11-22-22",
                Port = router.Port,
            });
        await using var client = result.Client;
        Assert.Equal("4C:5E:0C:11:22:24", result.Device.MacAddressText);
    }

    [Fact]
    public async Task KnownMac_RejectsANeighbouringRouterWithoutThatMac()
    {
        // MAC close to the known one, but no interface of this router has it: the next router from the same batch.
        await using var router = FakeRouterOs.StartFactoryRb960(password: "sticker");
        var e = await Assert.ThrowsAsync<MikrotikDeviceNotFoundException>(() => new MikrotikLoginScanner().FindAsync(
            new[] { Neighbor("4C:5E:0C:11:22:24", ipv4: IPAddress.Loopback) },
            new MikrotikLoginScanOptions
            {
                Credentials = { new MikrotikCredentials("admin", "sticker") },
                KnownMac = "4C:5E:0C:11:22:2C",
                Port = router.Port,
            }));
        var attempt = Assert.Single(e.Attempts);
        Assert.Equal(MikrotikLoginOutcome.WrongDevice, attempt.Outcome);
        Assert.Contains("4C:5E:0C:11:22:2C", e.Message);
    }

    [Fact]
    public async Task KnownMac_NeverSendsCredentialsToAnUnrelatedRouter()
    {
        await using var router = FakeRouterOs.StartFactoryRb960(password: "sticker");
        var e = await Assert.ThrowsAsync<MikrotikDeviceNotFoundException>(() => new MikrotikLoginScanner().FindAsync(
            new[] { Neighbor("D4:01:C3:AA:BB:CC", ipv4: IPAddress.Loopback) },
            new MikrotikLoginScanOptions
            {
                Credentials = { new MikrotikCredentials("admin", "sticker") },
                KnownMac = "4C:5E:0C:11:22:22",
                Port = router.Port,
            }));
        Assert.Empty(e.Attempts);
        Assert.Contains("D4:01:C3:AA:BB:CC", e.Message);
        Assert.Contains("replaced", e.Message);
    }

    [Theory]
    [InlineData("4C:5E:0C:11:22:22", "4C:5E:0C:11:22:26", true)]
    [InlineData("4C:5E:0C:11:22:FE", "4C:5E:0C:11:23:01", true)] // carry into the fifth byte
    [InlineData("4C:5E:0C:11:22:22", "4C:5E:0C:11:22:40", false)]
    [InlineData("4C:5E:0C:11:22:22", "D4:01:C3:11:22:23", false)] // other vendor prefix
    public void MikrotikMac_IsNear(string known, string candidate, bool expected) =>
        Assert.Equal(expected, MikrotikMac.IsNear(LinkLocal.ParseMac(known), LinkLocal.ParseMac(candidate)));

    [Fact]
    public async Task EmptyNetwork_GivesAClearError()
    {
        var e = await Assert.ThrowsAsync<MikrotikDeviceNotFoundException>(() => new MikrotikLoginScanner().FindAsync(
            Array.Empty<MikrotikNeighbor>(),
            new MikrotikLoginScanOptions { Credentials = { new MikrotikCredentials("admin", "x") } }));
        Assert.Contains("LAN port", e.Message);
    }
}
