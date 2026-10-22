using ITBees.Mikrotik.Configuration;
using ITBees.Mikrotik.Provisioning;
using ITBees.Mikrotik.Status;
using ITBees.Mikrotik.WireGuard;

namespace ITBees.Mikrotik.Tests;

public class ProvisionerTests
{
    private static async Task<MikrotikProvisioningResult> ApplyAsync(FakeRouterOs fake, string password, MikrotikConfigurationPackage package, MikrotikProvisioningOptions? options = null)
    {
        await using var client = await MikrotikClient.ConnectAsync(fake.Options(password));
        return await new MikrotikProvisioner().ApplyAsync(client, package, options);
    }

    private static string Describe(MikrotikProvisioningResult result) =>
        string.Join("\n", result.Steps.Select(s => s.ToString()).Concat(result.Changes.Select(c => c.ToString())).Append(result.Error ?? string.Empty));

    [Fact]
    public async Task FactoryRouter_BecomesAParkingRouter()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        // The computer is on the LAN at 192.168.88.x: replacing that address ends the session.
        fake.DropConnectionAfter = (path, attributes) => path == "/ip/address/set" && attributes.GetValueOrDefault("address") == "10.64.12.1/24";

        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage(), new MikrotikProvisioningOptions { SessionRouterAddress = "192.168.88.1" });

        Assert.True(result.Success, Describe(result));
        Assert.True(result.PasswordChanged);
        Assert.True(result.ReconnectRequired);
        Assert.True(result.LteDetected);
        Assert.Equal("10.0.5.23/24", result.WanAddress);
        Assert.Equal("10.0.5.1", result.WanGateway);
        Assert.Equal("10.64.12.1", result.LanRouterAddress);
        Assert.Equal(TestData.RouterKeys.PublicKey, result.VpnPublicKey);
        Assert.Equal(new[] { "10.250.0.12/32", "10.64.12.0/24" }, result.VpnHubPeer!.AllowedIps);

        // The LAN address is the very last write.
        Assert.StartsWith("/ip/address/set", fake.WriteLog[^1]);

        // Identity, password, time.
        Assert.Equal("octopark-test-p12", fake.Singletons["/system/identity"]["name"]);
        Assert.Equal(TestData.NewPassword, fake.Row("/user", "name", "admin")!["password"]);
        Assert.Equal("Europe/Warsaw", fake.Singletons["/system/clock"]["time-zone-name"]);

        // LAN: only the new address, new pool, DHCP network, static lease, router.lan.
        var lanAddresses = fake.Table("/ip/address").Where(a => a["interface"] == "bridge").ToList();
        Assert.Equal("10.64.12.1/24", Assert.Single(lanAddresses)["address"]);
        Assert.Equal("10.64.12.100-10.64.12.250", fake.Row("/ip/pool", "name", "itbees-lan")!["ranges"]);
        Assert.Null(fake.Row("/ip/pool", "name", "default-dhcp"));
        Assert.Equal("10.64.12.1", Assert.Single(fake.Table("/ip/dhcp-server/network"))["gateway"]);
        Assert.Equal("itbees-lan", fake.Row("/ip/dhcp-server", "name", "defconf")!["address-pool"]);
        var lease = fake.Row("/ip/dhcp-server/lease", "mac-address", "00:11:22:33:44:55")!;
        Assert.Equal("10.64.12.20", lease["address"]);
        Assert.Equal("itbees:lease barrier entry", lease["comment"]);
        Assert.Equal("10.64.12.1", fake.Row("/ip/dns/static", "name", "router.lan")!["address"]);

        // WAN: DHCP client without its own default route, lease script installed.
        var wan = fake.Row("/ip/dhcp-client", "interface", "ether1")!;
        Assert.Equal("no", wan["add-default-route"]);
        Assert.Equal("no", wan["use-peer-dns"]);
        Assert.Contains("itbees:wan-check-", wan["script"]);
        Assert.Equal("1.1.1.1,8.8.8.8", fake.Singletons["/ip/dns"]["servers"]);

        // LTE (HiLink): DHCP client with a backup default route.
        var lte = fake.Row("/ip/dhcp-client", "interface", "lte1")!;
        Assert.Equal("yes", lte["add-default-route"]);
        Assert.Equal("10", lte["default-route-distance"]);

        // Failover: recursive routes through the check hosts, pinned to the current WAN gateway.
        var check1 = fake.Row("/ip/route", "comment", "itbees:wan-check-1")!;
        Assert.Equal("1.0.0.1/32", check1["dst-address"]);
        Assert.Equal("10.0.5.1", check1["gateway"]);
        var default1 = fake.Row("/ip/route", "comment", "itbees:wan-default-1")!;
        Assert.Equal(("1.0.0.1", "1", "ping", "11"), (default1["gateway"], default1["distance"], default1["check-gateway"], default1["target-scope"]));
        Assert.Equal("2", fake.Row("/ip/route", "comment", "itbees:wan-default-2")!["distance"]);
        Assert.NotNull(fake.Row("/tool/netwatch", "comment", "itbees:uplink-monitor"));

        // Interface lists.
        Assert.Equal(new[] { "ether1", "lte1" }, fake.Table("/interface/list/member").Where(m => m["list"] == "WAN").Select(m => m["interface"]).OrderBy(x => x));
        Assert.Equal("wg-octopark", Assert.Single(fake.Table("/interface/list/member"), m => m["list"] == "VPN")["interface"]);

        // Firewall: managed rules on top in order, factory rules gone, dynamic rule untouched.
        var filter = fake.Table("/ip/firewall/filter").Where(r => r.GetValueOrDefault("dynamic") != "true").ToList();
        Assert.All(filter, r => Assert.StartsWith("itbees:fw4-", r["comment"]));
        Assert.Equal("itbees:fw4-in-established", filter[0]["comment"]);
        Assert.Equal("itbees:fw4-in-drop", filter.Last(r => r["chain"] == "input")["comment"]);
        Assert.Equal("itbees:fw4-fw-drop", filter.Last(r => r["chain"] == "forward")["comment"]);
        Assert.Single(fake.Table("/ip/firewall/filter"), r => r.GetValueOrDefault("dynamic") == "true");
        Assert.Equal("itbees:masquerade", Assert.Single(fake.Table("/ip/firewall/nat"))["comment"]);
        Assert.Equal("itbees:fw6-in-established", fake.Table("/ipv6/firewall/filter")[0]["comment"]);

        // Services and discovery.
        Assert.Equal("yes", fake.Row("/ip/service", "name", "telnet")!["disabled"]);
        Assert.Equal("false", fake.Row("/ip/service", "name", "api")!["disabled"]);
        Assert.Equal("no", fake.Singletons["/tool/bandwidth-server"]["enabled"]);

        // VPN.
        var wg = fake.Row("/interface/wireguard", "name", "wg-octopark")!;
        Assert.Equal(TestData.RouterKeys.PublicKey, wg["public-key"]);
        var peer = Assert.Single(fake.Table("/interface/wireguard/peers"));
        Assert.Equal(TestData.HubKeys.PublicKey, peer["public-key"]);
        Assert.Equal("vpn.octopark.example", peer["endpoint-address"]);
        Assert.Equal("10.250.0.0/16", peer["allowed-address"]);
        Assert.Equal("25s", peer["persistent-keepalive"]);
        Assert.Equal("10.250.0.12/16", fake.Row("/ip/address", "interface", "wg-octopark")!["address"]);
        Assert.Contains("last-handshake", fake.Row("/system/script", "name", "itbees-vpn-watchdog")!["source"]);
        Assert.Equal("1m", fake.Row("/system/scheduler", "name", "itbees-vpn-watchdog")!["interval"]);
    }

    [Fact]
    public async Task SecondApply_ChangesNothing()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.ParkingPackage();

        var first = await ApplyAsync(fake, TestData.FactoryPassword, package);
        Assert.True(first.Success, Describe(first));
        Assert.False(first.ReconnectRequired);

        var second = await ApplyAsync(fake, TestData.NewPassword, package);
        Assert.True(second.Success, Describe(second));
        Assert.True(second.ChangeCount == 0, Describe(second));
        Assert.All(second.Steps, s => Assert.NotEqual(ProvisioningStepStatus.Changed, s.Status));
    }

    [Fact]
    public async Task FirewallChanges_NeverPutADropAboveTheAcceptRules()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var violations = new List<string>();
        fake.AfterWrite = (router, path) =>
        {
            if (!path.StartsWith("/ip/firewall/filter", StringComparison.Ordinal))
                return;
            var rules = router.Table("/ip/firewall/filter").Where(r => r.GetValueOrDefault("dynamic") != "true").ToList();
            var established = rules.FindIndex(r => r["chain"] == "input" && r["action"] == "accept" && r.GetValueOrDefault("connection-state", string.Empty).Contains("established"));
            var fullDrop = rules.FindIndex(r => r["chain"] == "input" && r["action"] == "drop" && r.Keys.All(k => k is ".id" or "chain" or "action" or "comment" or "disabled" or "dynamic"));
            if (fullDrop >= 0 && (established < 0 || established > fullDrop))
                violations.Add($"after {path}: drop at {fullDrop}, established accept at {established}");
        };

        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage());

        Assert.True(result.Success, Describe(result));
        Assert.Empty(violations);
    }

    [Fact]
    public async Task DefaultRoute_NeverDisappearsDuringApply()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var gaps = new List<string>();
        fake.AfterWrite = (router, path) =>
        {
            // Like RouterOS: the lease's dynamic default route goes away once the client stops adding it.
            if (router.Row("/ip/dhcp-client", "interface", "ether1")?.GetValueOrDefault("add-default-route") == "no")
                router.Tables["/ip/route"].RemoveAll(r => r.GetValueOrDefault("dynamic") == "true" && r["dst-address"] == "0.0.0.0/0");
            if (!router.Tables["/ip/route"].Any(r => r["dst-address"] == "0.0.0.0/0"))
                gaps.Add(path);
        };

        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage());

        Assert.True(result.Success, Describe(result));
        Assert.Empty(gaps);
    }

    [Fact]
    public async Task DryRun_ReportsChanges_ButWritesNothing()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var before = fake.Snapshot();

        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage(), new MikrotikProvisioningOptions { DryRun = true });

        Assert.True(result.Success, Describe(result));
        Assert.True(result.DryRun);
        Assert.True(result.ChangeCount > 30, Describe(result));
        Assert.Contains(result.Changes, c => c.Command.StartsWith("/user set", StringComparison.Ordinal) && c.Command.Contains("password=***"));
        Assert.Empty(fake.WriteLog);
        Assert.Equal(before, fake.Snapshot());
    }

    [Fact]
    public async Task SessionOverWan_IsRefused_BeforeAnyChange()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage(), new MikrotikProvisioningOptions { SessionRouterAddress = "10.0.5.23" });

        Assert.False(result.Success);
        Assert.Equal(ProvisioningStepStatus.Failed, result.Steps[0].Status);
        Assert.Contains("ether1", result.Error);
        Assert.All(result.Steps.Skip(1), s => Assert.Equal(ProvisioningStepStatus.NotRun, s.Status));
        Assert.Empty(fake.WriteLog);
    }

    [Fact]
    public async Task RouterOs6_IsRefused()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960(version: "6.49.10 (long-term)");
        var result = await ApplyAsync(fake, TestData.FactoryPassword, TestData.ParkingPackage());
        Assert.False(result.Success);
        Assert.Contains("RouterOS 7 is required", result.Error);
        Assert.Empty(fake.WriteLog);
    }

    [Fact]
    public async Task LanOverlappingTheSiteNetwork_IsRefused()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.ParkingPackage();
        package.Lan.Address = "10.0.5.1/24";
        package.Lan.Dhcp.StaticLeases.Clear();

        var result = await ApplyAsync(fake, TestData.FactoryPassword, package);

        Assert.False(result.Success);
        Assert.Contains("overlaps the parking LAN", result.Error);
        Assert.Empty(fake.WriteLog);
    }

    [Fact]
    public async Task MissingModem_SkipsLte_AndLaterApplyAddsIt()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960(withLte: false);
        var package = TestData.ParkingPackage();

        var result = await ApplyAsync(fake, TestData.FactoryPassword, package);
        Assert.True(result.Success, Describe(result));
        Assert.False(result.LteDetected);
        Assert.Contains(result.Warnings, w => w.Contains("LTE modem not detected"));
        Assert.Equal(ProvisioningStepStatus.Skipped, result.Steps.Single(s => s.Name == "LTE backup").Status);
        Assert.Equal(new[] { "ether1" }, fake.Table("/interface/list/member").Where(m => m["list"] == "WAN").Select(m => m["interface"]));

        // The modem is plugged in later.
        fake.AddRow("/interface", new() { ["name"] = "lte1", ["type"] = "lte", ["running"] = "true" });
        var again = await ApplyAsync(fake, TestData.NewPassword, package);
        Assert.True(again.Success, Describe(again));
        Assert.NotNull(fake.Row("/ip/dhcp-client", "interface", "lte1"));
        Assert.Contains(fake.Table("/interface/list/member"), m => m["list"] == "WAN" && m["interface"] == "lte1");
    }

    [Fact]
    public async Task DisablingVpn_RemovesTunnelAndWatchdog()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.ParkingPackage();
        Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, package)).Success);

        package.Vpn.Enabled = false;
        var result = await ApplyAsync(fake, TestData.NewPassword, package);

        Assert.True(result.Success, Describe(result));
        Assert.Empty(fake.Table("/interface/wireguard"));
        Assert.Empty(fake.Table("/interface/wireguard/peers"));
        Assert.Empty(fake.Table("/system/scheduler"));
        Assert.Null(fake.Row("/ip/address", "interface", "wg-octopark"));
        Assert.DoesNotContain(fake.Table("/ip/firewall/filter"), r => r.GetValueOrDefault("comment") == "itbees:fw4-in-vpn");
    }

    [Fact]
    public async Task RouterGeneratedVpnKey_IsReturnedForTheHub()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.ParkingPackage();
        package.Vpn.PrivateKey = null;

        var result = await ApplyAsync(fake, TestData.FactoryPassword, package);

        Assert.True(result.Success, Describe(result));
        Assert.Equal(fake.Row("/interface/wireguard", "name", "wg-octopark")!["public-key"], result.VpnPublicKey);
        Assert.Contains("PublicKey = " + result.VpnPublicKey, result.VpnHubPeer!.ToWgQuickSection());
    }

    [Fact]
    public async Task Status_ReportsUplinkLeaseAndVpn()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.ParkingPackage();
        Assert.True((await ApplyAsync(fake, TestData.FactoryPassword, package)).Success);
        // What the router would show once the primary check route is active and the tunnel is up.
        var route = fake.Row("/ip/route", "comment", "itbees:wan-default-1")!;
        fake.Tables["/ip/route"].RemoveAll(r => r.GetValueOrDefault("dynamic") == "true");
        fake.Tables["/ip/route"].Single(r => r[".id"] == route[".id"])["active"] = "true";
        fake.Tables["/interface/wireguard/peers"][0]["last-handshake"] = "41s";

        await using var client = await MikrotikClient.ConnectAsync(fake.Options(TestData.NewPassword));
        var status = await new MikrotikStatusReader().ReadAsync(client, package);

        Assert.Equal(MikrotikUplink.Primary, status.ActiveUplink);
        Assert.Equal("10.0.5.23/24", status.Wan.Address);
        Assert.True(status.Lte.Detected);
        Assert.True(status.Vpn.IsConnected);
        Assert.Equal("10.250.0.12/16", status.Vpn.Address);
        Assert.Equal(TimeSpan.FromSeconds(41), status.Vpn.LastHandshake);
    }

    [Fact]
    public async Task InvalidPackage_IsRejectedBeforeContactingTheRouter()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var package = TestData.ParkingPackage();
        package.Security.AdminPassword = "short";
        await using var client = await MikrotikClient.ConnectAsync(fake.Options(TestData.FactoryPassword));

        var e = await Assert.ThrowsAsync<MikrotikConfigurationException>(() => new MikrotikProvisioner().ApplyAsync(client, package));
        Assert.Contains(e.Errors, x => x.Contains("at least"));
        Assert.Empty(fake.WriteLog);
    }

    [Fact]
    public async Task Service_SetupAsync_FindsRouterAndApplies_ThenIsRepeatable()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        // Discovery is replaced by a filter-free list pointing at the emulator: covered by DiscoveryTests.
        var neighbor = new Discovery.MikrotikNeighbor { MacAddress = Discovery.LinkLocal.ParseMac("4C:5E:0C:11:22:23"), Ipv4Address = System.Net.IPAddress.Loopback };
        var package = TestData.ParkingPackage();
        var scanner = new Discovery.MikrotikLoginScanner();
        var options = new Discovery.MikrotikLoginScanOptions
        {
            Credentials = { new Discovery.MikrotikCredentials("admin", TestData.FactoryPassword), new Discovery.MikrotikCredentials("admin", TestData.NewPassword) },
            Port = fake.Port,
        };

        var scan = await scanner.FindAsync(new[] { neighbor }, options);
        await using (scan.Client)
            Assert.True((await new MikrotikService().ApplyConfigurationAsync(scan.Client, package)).Success);

        // Second time the sticker password no longer works, the package password does.
        var rescan = await scanner.FindAsync(new[] { neighbor }, options);
        await using (rescan.Client)
            Assert.Equal(TestData.NewPassword, rescan.Credentials.Password);
    }
}
