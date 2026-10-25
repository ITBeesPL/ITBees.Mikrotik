using ITBees.Mikrotik.Configuration;
using ITBees.Mikrotik.Provisioning;
using ITBees.Mikrotik.Status;

namespace ITBees.Mikrotik.Tests;

/// <summary>
/// <see cref="LanMode.SharedSiteNetwork"/>: the parking devices stay on the site switches; ether1 joins the bridge, so
/// the router's other ports (camera, payment terminal, intercom in an entry column) are site-network ports too, and
/// the router is the gateway of the parking subnet next to the site's own DHCP network.
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

    private static List<string> Comments(FakeRouterOs fake, string menu) =>
        fake.Table(menu).Where(r => r.GetValueOrDefault("dynamic") != "true").Select(r => r.GetValueOrDefault("comment", string.Empty)).ToList();

    private static IEnumerable<string> ListMembers(FakeRouterOs fake, string list) =>
        fake.Table("/interface/list/member").Where(m => m["list"] == list).Select(m => m["interface"]).OrderBy(x => x);

    [Fact]
    public async Task FactoryRouter_FirstApplyFromEther2_PutsEther1IntoTheBridge()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        // A factory router accepts logins only on ether2-ether5, so the column is there at 192.168.88.x;
        // re-addressing the bridge ends the session.
        fake.DropConnectionAfter = (path, attributes) => path == "/ip/address/set" && attributes.GetValueOrDefault("address") == "10.64.12.1/24";

        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.SharedSitePackage(), new MikrotikProvisioningOptions { SessionRouterAddress = "192.168.88.1" });

        Assert.True(result.Success, Describe(result));
        Assert.True(result.ReconnectRequired);
        Assert.Equal("10.64.12.1", result.LanRouterAddress);
        Assert.Contains(result.Warnings, w => w.Contains("shared site network"));
        Assert.StartsWith("/ip/address/set", fake.WriteLog[^1]);

        // One bridge: ether1 joined ether2-ether5; the site lease and the parking address are both on it.
        Assert.Equal("bridge", fake.Row("/interface/bridge/port", "interface", "ether1")!["bridge"]);
        Assert.Equal("10.64.12.1/24", Assert.Single(StaticAddresses(fake, "bridge"))["address"]);
        Assert.Empty(StaticAddresses(fake, "ether1"));
        var wan = fake.Row("/ip/dhcp-client", "interface", "bridge")!;
        Assert.Equal(("no", "itbees:wan"), (wan["add-default-route"], wan["comment"]));
        Assert.Null(fake.Row("/ip/dhcp-client", "interface", "ether1"));
        Assert.Equal(("10.0.5.23/24", "10.0.5.1"), (result.WanAddress, result.WanGateway));

        // No DHCP server anywhere, and the factory one went off before ether1 joined the bridge.
        Assert.All(fake.Table("/ip/dhcp-server"), s => Assert.Equal("yes", s["disabled"]));
        var serverOff = fake.WriteLog.FindIndex(w => w.StartsWith("/ip/dhcp-server/set", StringComparison.Ordinal) && w.Contains("disabled=yes"));
        var ether1Joins = fake.WriteLog.FindIndex(w => w.StartsWith("/interface/bridge/port/add", StringComparison.Ordinal) && w.Contains("interface=ether1"));
        Assert.True(serverOff >= 0 && serverOff < ether1Joins, string.Join("\n", fake.WriteLog));

        // The bridge carries the uplink (NAT, failover) and stays the LAN for discovery / MAC-Winbox.
        Assert.Equal(new[] { "bridge", "ether1", "lte1" }, ListMembers(fake, "WAN"));
        Assert.Equal(new[] { "bridge" }, ListMembers(fake, "LAN"));

        // IPv4 only from the parking subnet; nothing trusts the whole bridge (= the site network).
        var filter = fake.Table("/ip/firewall/filter").Where(r => r.GetValueOrDefault("dynamic") != "true").ToList();
        var comments = filter.Select(r => r["comment"]).ToList();
        Assert.DoesNotContain("itbees:fw4-in-lan", comments);
        Assert.DoesNotContain("itbees:fw4-fw-lan-wan", comments);
        Assert.DoesNotContain("itbees:fw4-fw-vpn-lan", comments);
        Assert.DoesNotContain("itbees:fw4-fw-lan-vpn", comments);
        var input = filter.Single(r => r["comment"] == "itbees:fw4-in-site-lan");
        Assert.Equal(("bridge", "10.64.12.0/24"), (input["in-interface"], input["src-address"]));
        Assert.True(comments.IndexOf("itbees:fw4-in-site-lan") < comments.IndexOf("itbees:fw4-in-drop"));
        var forward = filter.Single(r => r["comment"] == "itbees:fw4-fw-site-lan-wan");
        Assert.Equal(("bridge", "10.64.12.0/24", "WAN"), (forward["in-interface"], forward["src-address"], forward["out-interface-list"]));
        var vpnToLan = filter.Single(r => r["comment"] == "itbees:fw4-fw-vpn-site-lan");
        Assert.Equal(("VPN", "bridge", "10.64.12.0/24"), (vpnToLan["in-interface-list"], vpnToLan["out-interface"], vpnToLan["dst-address"]));
        Assert.Contains("itbees:fw4-fw-site-lan-vpn", comments);
        Assert.True(comments.IndexOf("itbees:fw4-fw-site-lan-wan") < comments.IndexOf("itbees:fw4-fw-drop"));

        // IPv6: link-local service access only, nothing routed.
        var ipv6 = Comments(fake, "/ipv6/firewall/filter");
        Assert.Contains("itbees:fw6-in-lan-link-local", ipv6);
        Assert.DoesNotContain("itbees:fw6-in-lan", ipv6);
        Assert.DoesNotContain("itbees:fw6-fw-lan-wan", ipv6);
        Assert.Equal("fe80::/10", fake.Row("/ipv6/firewall/filter", "comment", "itbees:fw6-in-lan-link-local")!["src-address"]);

        // The password check (a second login from 192.168.88.x) ran before the strict firewall went in.
        var passwordSet = fake.WriteLog.FindLastIndex(w => w.StartsWith("/user/set", StringComparison.Ordinal));
        var firewallStart = fake.WriteLog.FindIndex(w => w.StartsWith("/ip/firewall/filter/", StringComparison.Ordinal));
        Assert.True(passwordSet >= 0 && passwordSet < firewallStart, string.Join("\n", fake.WriteLog));

        // Devices must keep the router as gateway; the SIP helper keeps the RouterOS default.
        Assert.Equal("no", fake.Singletons["/ip/settings"]["send-redirects"]);
        Assert.Equal("false", fake.Row("/ip/firewall/service-port", "name", "sip")!["disabled"]);

        Assert.Equal(new[] { "10.250.0.12/32", "10.64.12.0/24" }, result.VpnHubPeer!.AllowedIps);
    }

    [Fact]
    public async Task SecondApply_FromTheParkingSubnetOrTheVpn_ChangesNothing()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.SharedSitePackage();
        Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, package)).Success);

        // A column on any port (site switch, router port) reaches the router at its parking address on the bridge.
        var fromSite = await ApplyAsync(fake, TestData.NewPassword, package, new MikrotikProvisioningOptions { SessionRouterAddress = "10.64.12.1" });
        Assert.True(fromSite.Success, Describe(fromSite));
        Assert.True(fromSite.ChangeCount == 0, Describe(fromSite));
        Assert.False(fromSite.ReconnectRequired);

        // Once ether1 is in the bridge nothing disruptive is left, so the VPN may apply too.
        var overVpn = await ApplyAsync(fake, TestData.NewPassword, package, new MikrotikProvisioningOptions { SessionRouterAddress = "10.250.0.12" });
        Assert.True(overVpn.Success, Describe(overVpn));
        Assert.True(overVpn.ChangeCount == 0, Describe(overVpn));
    }

    [Theory]
    [InlineData("10.0.5.23")]   // the site lease on ether1
    [InlineData("10.250.0.12")] // the VPN address (re-applying an own-ports router remotely)
    public async Task MovingEther1IntoTheBridge_FromASessionItWouldCut_IsRefused(string sessionAddress)
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        if (sessionAddress.StartsWith("10.250.", StringComparison.Ordinal))
            Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage())).Success);
        var writes = fake.WriteLog.Count;
        var password = sessionAddress.StartsWith("10.250.", StringComparison.Ordinal) ? TestData.NewPassword : TestData.FactoryPassword;

        var result = await ApplyAsync(fake, password, TestData.SharedSitePackage(), new MikrotikProvisioningOptions { SessionRouterAddress = sessionAddress });

        Assert.False(result.Success);
        Assert.Contains("moves ether1 into the bridge", result.Error);
        Assert.Equal(writes, fake.WriteLog.Count);
    }

    [Fact]
    public async Task RouterFromTheSinglePortLayout_IsMovedToTheBridge()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        // What the first shared-network version left: the parking address on ether1, the bridge without IPv4.
        fake.Tables["/ip/address"].RemoveAll(a => a["address"] == "192.168.88.1/24");
        fake.AddRow("/ip/address", new() { ["address"] = "10.64.12.1/24", ["interface"] = "ether1", ["comment"] = "itbees:lan" });

        // The column is cabled into ether2 and reaches the router over IPv6 link-local.
        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.SharedSitePackage(), new MikrotikProvisioningOptions { SessionRouterAddress = "fe80::4e5e:cff:fe11:2223" });

        Assert.True(result.Success, Describe(result));
        Assert.False(result.ReconnectRequired);
        Assert.Empty(StaticAddresses(fake, "ether1"));
        Assert.Equal("10.64.12.1/24", Assert.Single(StaticAddresses(fake, "bridge"))["address"]);
        Assert.Equal("bridge", fake.Row("/interface/bridge/port", "interface", "ether1")!["bridge"]);
    }

    [Fact]
    public async Task SwitchingModes_MovesEther1AndTheLeaseBetweenLayouts()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage())).Success);

        var shared = await ApplyAsync(fake, TestData.NewPassword, TestData.SharedSitePackage());
        Assert.True(shared.Success, Describe(shared));
        Assert.NotNull(fake.Row("/interface/bridge/port", "interface", "ether1"));
        Assert.NotNull(fake.Row("/ip/dhcp-client", "interface", "bridge"));
        Assert.All(fake.Table("/ip/dhcp-server"), s => Assert.Equal("yes", s["disabled"]));

        var back = await ApplyAsync(fake, TestData.NewPassword, TestData.ParkingPackage());
        Assert.True(back.Success, Describe(back));
        Assert.Null(fake.Row("/interface/bridge/port", "interface", "ether1"));
        Assert.Null(fake.Row("/ip/dhcp-client", "interface", "bridge"));
        Assert.Equal("itbees:wan", fake.Row("/ip/dhcp-client", "interface", "ether1")!["comment"]);
        Assert.Equal("10.64.12.1/24", Assert.Single(StaticAddresses(fake, "bridge"))["address"]);
        Assert.Contains(fake.Table("/ip/dhcp-server"), s => s["interface"] == "bridge" && s["disabled"] == "no");
        Assert.Equal(new[] { "ether1", "lte1" }, ListMembers(fake, "WAN"));
        Assert.Contains("itbees:fw4-in-lan", Comments(fake, "/ip/firewall/filter"));
        Assert.DoesNotContain(Comments(fake, "/ip/firewall/filter"), c => c.Contains("site-lan", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NewParkingSubnet_ReplacesTheAddressAndTheFirewallSource()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.SharedSitePackage();
        Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, package)).Success);

        package.Lan.Address = "10.64.13.1/24";
        var result = await ApplyAsync(fake, TestData.NewPassword, package);

        Assert.True(result.Success, Describe(result));
        Assert.Equal("10.64.13.1/24", Assert.Single(StaticAddresses(fake, "bridge"))["address"]);
        Assert.Equal("10.64.13.0/24", fake.Row("/ip/firewall/filter", "comment", "itbees:fw4-in-site-lan")!["src-address"]);
    }

    [Fact]
    public async Task SiteNetworkOverlappingTheParkingSubnet_IsRefused()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.SharedSitePackage();
        package.Lan.Address = "10.0.5.200/24";

        var result = await ApplyAsync(fake, TestData.FactoryPassword, package, new MikrotikProvisioningOptions { SessionRouterAddress = "192.168.88.1" });

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
        Assert.Contains(result.Changes, c => c.Command.StartsWith("/interface bridge port add", StringComparison.Ordinal) && c.Command.Contains("interface=ether1"));
        Assert.Empty(fake.WriteLog);
        Assert.Equal(before, fake.Snapshot());
    }

    [Fact]
    public async Task SipHelperSwitch_TurnsTheRouterOsAlgOffAndOn()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.SharedSitePackage();
        package.Nat.SipHelper = false;

        var off = await ApplyAsync(fake, TestData.FactoryPassword, package);
        Assert.True(off.Success, Describe(off));
        Assert.Equal("yes", fake.Row("/ip/firewall/service-port", "name", "sip")!["disabled"]);
        Assert.Equal("SIP helper off", off.Steps.Single(s => s.Name == "NAT").Message);
        Assert.Equal("false", fake.Row("/ip/firewall/service-port", "name", "ftp")!["disabled"]);

        package.Nat.SipHelper = true;
        var on = await ApplyAsync(fake, TestData.NewPassword, package);
        Assert.True(on.Success, Describe(on));
        Assert.Equal("no", fake.Row("/ip/firewall/service-port", "name", "sip")!["disabled"]);
    }

    [Fact]
    public async Task Status_ReadsTheSiteLeaseFromTheBridge()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.SharedSitePackage();
        Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, package)).Success);
        var route = fake.Row("/ip/route", "comment", "itbees:wan-default-1")!;
        fake.Tables["/ip/route"].RemoveAll(r => r.GetValueOrDefault("dynamic") == "true");
        fake.Tables["/ip/route"].Single(r => r[".id"] == route[".id"])["active"] = "true";

        await using var client = await MikrotikClient.ConnectAsync(fake.Options(TestData.NewPassword));
        var status = await new MikrotikStatusReader().ReadAsync(client, package);

        Assert.Equal(MikrotikUplink.Primary, status.ActiveUplink);
        Assert.Equal("ether1", status.Wan.Interface);
        Assert.True(status.Wan.Running);
        Assert.Equal(("bound", "10.0.5.23/24", "10.0.5.1"), (status.Wan.DhcpStatus, status.Wan.Address, status.Wan.Gateway));
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
    public void Mode_AndSipHelper_RoundTripThroughJson_AndOldPackagesKeepTheDefaults()
    {
        var package = TestData.SharedSitePackage();
        package.Nat.SipHelper = false;
        var json = package.ToJson();
        Assert.Contains("\"mode\": \"SharedSiteNetwork\"", json);
        Assert.DoesNotContain("wanAddressInterface", json);
        var back = MikrotikConfigurationPackage.FromJson(json);
        Assert.Equal((LanMode.SharedSiteNetwork, false), (back.Lan.Mode, back.Nat.SipHelper));
        Assert.Equal("bridge", back.WanAddressInterface);

        var old = MikrotikConfigurationPackage.FromJson("{\"lan\":{\"address\":\"10.64.12.1/24\"}}");
        Assert.Equal((LanMode.OwnPorts, true, "ether1"), (old.Lan.Mode, old.Nat.SipHelper, old.WanAddressInterface));
    }
}
