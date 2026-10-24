using ITBees.Mikrotik.Configuration;
using ITBees.Mikrotik.Provisioning;

namespace ITBees.Mikrotik.Tests;

/// <summary>
/// <see cref="LanMode.SharedSiteNetwork"/>: the parking devices stay on the site switches and the router, connected
/// with one cable (ether1), is their gateway in the parking subnet next to the site's own DHCP network.
/// </summary>
public class SharedSiteNetworkTests
{
    private static async Task<MikrotikProvisioningResult> ApplyAsync(FakeRouterOs fake, string password, MikrotikConfigurationPackage package, MikrotikProvisioningOptions? options = null)
    {
        await using var client = await MikrotikClient.ConnectAsync(fake.Options(password));
        return await new MikrotikProvisioner().ApplyAsync(client, package, options);
    }

    private static string Describe(MikrotikProvisioningResult result) =>
        string.Join("\n", result.Steps.Select(s => s.ToString()).Concat(result.Changes.Select(c => c.ToString())).Append(result.Error ?? string.Empty));

    private static List<Dictionary<string, string>> StaticAddresses(FakeRouterOs fake, string iface) =>
        fake.Table("/ip/address").Where(a => a["interface"] == iface && a.GetValueOrDefault("dynamic") != "true").ToList();

    [Fact]
    public async Task FactoryRouter_FirstApplyFromAServicePort_PutsTheParkingSubnetOnEther1()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        // A factory router is reachable only from ether2-ether5, so the column is plugged in there at 192.168.88.x;
        // removing that address from the bridge ends the session.
        var factoryLanId = fake.Row("/ip/address", "address", "192.168.88.1/24")![".id"];
        fake.DropConnectionAfter = (path, attributes) => path == "/ip/address/remove" && attributes.GetValueOrDefault(".id") == factoryLanId;

        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.SharedSitePackage(), new MikrotikProvisioningOptions { SessionRouterAddress = "192.168.88.1" });

        Assert.True(result.Success, Describe(result));
        Assert.True(result.ReconnectRequired);
        Assert.Equal("10.64.12.1", result.LanRouterAddress);
        Assert.Contains(result.Warnings, w => w.Contains("shared site network"));
        Assert.StartsWith("/ip/address/remove", fake.WriteLog[^1]);

        // The parking subnet sits on ether1 next to the site lease; the bridge keeps no IPv4 address.
        var lan = Assert.Single(StaticAddresses(fake, "ether1"));
        Assert.Equal(("10.64.12.1/24", "itbees:lan"), (lan["address"], lan["comment"]));
        Assert.NotNull(fake.Row("/ip/address", "address", "10.0.5.23/24"));
        Assert.Empty(StaticAddresses(fake, "bridge"));

        // No DHCP server anywhere: the site network has its own.
        Assert.All(fake.Table("/ip/dhcp-server"), s => Assert.Equal("yes", s["disabled"]));
        Assert.Equal("10.64.12.1", fake.Row("/ip/dns/static", "name", "router.lan")!["address"]);

        // The uplink is unchanged: DHCP client on ether1, LTE backup, failover routes.
        Assert.Equal("no", fake.Row("/ip/dhcp-client", "interface", "ether1")!["add-default-route"]);
        Assert.NotNull(fake.Row("/ip/route", "comment", "itbees:wan-default-1"));
        Assert.Equal(new[] { "ether1", "lte1" }, fake.Table("/interface/list/member").Where(m => m["list"] == "WAN").Select(m => m["interface"]).OrderBy(x => x));

        // Firewall: ether1 lets in the parking subnet only, the parking subnet is routed to the internet and the VPN.
        var filter = fake.Table("/ip/firewall/filter").Where(r => r.GetValueOrDefault("dynamic") != "true").ToList();
        var input = filter.Single(r => r["comment"] == "itbees:fw4-in-site-lan");
        Assert.Equal(("ether1", "10.64.12.0/24", "accept"), (input["in-interface"], input["src-address"], input["action"]));
        Assert.True(filter.IndexOf(input) < filter.FindIndex(r => r["comment"] == "itbees:fw4-in-drop"));
        var forward = filter.Single(r => r["comment"] == "itbees:fw4-fw-site-lan-wan");
        Assert.Equal(("ether1", "10.64.12.0/24", "WAN"), (forward["in-interface"], forward["src-address"], forward["out-interface-list"]));
        var vpnToLan = filter.Single(r => r["comment"] == "itbees:fw4-fw-vpn-site-lan");
        Assert.Equal(("VPN", "ether1", "10.64.12.0/24"), (vpnToLan["in-interface-list"], vpnToLan["out-interface"], vpnToLan["dst-address"]));
        Assert.NotNull(filter.SingleOrDefault(r => r["comment"] == "itbees:fw4-fw-site-lan-vpn"));
        Assert.True(filter.IndexOf(forward) < filter.FindIndex(r => r["comment"] == "itbees:fw4-fw-drop"));

        // Devices must keep the router as their gateway: no ICMP redirects to the site router.
        Assert.Equal("no", fake.Singletons["/ip/settings"]["send-redirects"]);

        // The hub routes the parking subnet to this router.
        Assert.Equal(new[] { "10.250.0.12/32", "10.64.12.0/24" }, result.VpnHubPeer!.AllowedIps);
    }

    [Fact]
    public async Task SessionFromTheSiteNetwork_IsAllowed_AndTheSecondApplyChangesNothing()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.SharedSitePackage();

        // The column reaches the router through ether1: refused in OwnPorts mode, normal here.
        var first = await ApplyAsync(fake, TestData.FactoryPassword, package, new MikrotikProvisioningOptions { SessionRouterAddress = "10.0.5.23" });
        Assert.True(first.Success, Describe(first));
        Assert.False(first.ReconnectRequired);

        // Later the column uses the router's parking address on ether1; the WAN step must not touch it.
        var second = await ApplyAsync(fake, TestData.NewPassword, package, new MikrotikProvisioningOptions { SessionRouterAddress = "10.64.12.1" });
        Assert.True(second.Success, Describe(second));
        Assert.True(second.ChangeCount == 0, Describe(second));
        Assert.Equal("10.64.12.1/24", Assert.Single(StaticAddresses(fake, "ether1"))["address"]);
    }

    [Fact]
    public async Task SwitchingModes_MovesTheLanAddressBetweenBridgeAndEther1()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage())).Success);
        Assert.Equal("10.64.12.1/24", Assert.Single(StaticAddresses(fake, "bridge"))["address"]);

        var shared = await ApplyAsync(fake, TestData.NewPassword, TestData.SharedSitePackage());
        Assert.True(shared.Success, Describe(shared));
        Assert.Empty(StaticAddresses(fake, "bridge"));
        Assert.Equal("10.64.12.1/24", Assert.Single(StaticAddresses(fake, "ether1"))["address"]);
        Assert.All(fake.Table("/ip/dhcp-server"), s => Assert.Equal("yes", s["disabled"]));

        var back = await ApplyAsync(fake, TestData.NewPassword, TestData.ParkingPackage());
        Assert.True(back.Success, Describe(back));
        Assert.Empty(StaticAddresses(fake, "ether1"));
        Assert.Equal("10.64.12.1/24", Assert.Single(StaticAddresses(fake, "bridge"))["address"]);
        Assert.Contains(fake.Table("/ip/dhcp-server"), s => s["interface"] == "bridge" && s["disabled"] == "no");
        Assert.DoesNotContain(fake.Table("/ip/firewall/filter"), r => r.GetValueOrDefault("comment", string.Empty).Contains("site-lan"));
    }

    [Fact]
    public async Task NewParkingSubnet_ReplacesTheOldAddressOnEther1()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.SharedSitePackage();
        Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, package)).Success);

        package.Lan.Address = "10.64.13.1/24";
        var result = await ApplyAsync(fake, TestData.NewPassword, package);

        Assert.True(result.Success, Describe(result));
        Assert.Equal("10.64.13.1/24", Assert.Single(StaticAddresses(fake, "ether1"))["address"]);
        Assert.Equal("10.64.13.0/24", fake.Row("/ip/firewall/filter", "comment", "itbees:fw4-in-site-lan")!["src-address"]);
    }

    [Fact]
    public async Task SiteNetworkOverlappingTheParkingSubnet_IsRefused()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.SharedSitePackage();
        package.Lan.Address = "10.0.5.200/24";

        var result = await ApplyAsync(fake, TestData.FactoryPassword, package, new MikrotikProvisioningOptions { SessionRouterAddress = "10.0.5.23" });

        Assert.False(result.Success);
        Assert.Contains("overlaps the parking LAN", result.Error);
        Assert.Empty(fake.WriteLog);
    }

    [Fact]
    public async Task DryRun_WritesNothing()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var before = fake.Snapshot();

        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.SharedSitePackage(), new MikrotikProvisioningOptions { DryRun = true, SessionRouterAddress = "192.168.88.1" });

        Assert.True(result.Success, Describe(result));
        Assert.Contains(result.Changes, c => c.Command.StartsWith("/ip address add", StringComparison.Ordinal) && c.Command.Contains("interface=ether1"));
        Assert.Empty(fake.WriteLog);
        Assert.Equal(before, fake.Snapshot());
    }

    [Fact]
    public void Validation_RequiresNoDhcpServer_AndWarnsAboutStaticLeases()
    {
        var package = TestData.ParkingPackage();
        package.Lan.Mode = LanMode.SharedSiteNetwork;

        var result = package.Validate();

        Assert.Contains(result.Errors, e => e.Contains("Lan.Dhcp.Enabled must be false"));
        Assert.Contains(result.Warnings, w => w.Contains("StaticLeases are ignored"));

        package.Lan.Dhcp.Enabled = false;
        Assert.True(package.Validate().IsValid, string.Join("; ", package.Validate().Errors));
    }

    [Fact]
    public void Mode_RoundTripsThroughJson_AndOldPackagesKeepOwnPorts()
    {
        var json = TestData.SharedSitePackage().ToJson();
        Assert.Contains("\"mode\": \"SharedSiteNetwork\"", json);
        Assert.Equal(LanMode.SharedSiteNetwork, MikrotikConfigurationPackage.FromJson(json).Lan.Mode);

        var old = MikrotikConfigurationPackage.FromJson("{\"lan\":{\"address\":\"10.64.12.1/24\"}}");
        Assert.Equal(LanMode.OwnPorts, old.Lan.Mode);
    }
}
