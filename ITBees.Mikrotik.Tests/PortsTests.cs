using ITBees.Mikrotik.Status;

namespace ITBees.Mikrotik.Tests;

public class PortsTests
{
    private static FakeRouterOs RouterWithACamera()
    {
        var fake = FakeRouterOs.StartFactoryRb960(password: "pass");
        var ether2 = fake.Tables["/interface"].Single(r => r["name"] == "ether2");
        ether2["last-link-up-time"] = "2026-10-25 11:06:13";
        ether2["link-downs"] = "3";
        fake.Tables["/interface"].Single(r => r["name"] == "ether3")["last-link-down-time"] = "2026-10-25 10:31:02";
        // The camera on ether2, and the router's own MAC (local) on the same port.
        fake.AddRow("/interface/bridge/host", new() { ["mac-address"] = "d8:3a:dd:12:34:56", ["on-interface"] = "ether2", ["bridge"] = "bridge", ["dynamic"] = "true" });
        fake.AddRow("/interface/bridge/host", new() { ["mac-address"] = "4C:5E:0C:11:22:23", ["on-interface"] = "ether2", ["bridge"] = "bridge", ["local"] = "true" });
        fake.AddRow("/ip/arp", new() { ["address"] = "10.64.10.15", ["mac-address"] = "D8:3A:DD:12:34:56", ["interface"] = "bridge", ["status"] = "reachable" });
        fake.AddRow("/ip/arp", new() { ["address"] = "10.64.10.99", ["mac-address"] = "D8:3A:DD:12:34:56", ["interface"] = "bridge", ["status"] = "failed" });
        fake.AddRow("/ip/dhcp-server/lease", new() { ["address"] = "192.168.88.250", ["mac-address"] = "D8:3A:DD:12:34:56", ["host-name"] = "ipcam", ["server"] = "defconf" });
        fake.PoeMonitor["ether2"] = ("powered-on", "3.4W");
        return fake;
    }

    [Fact]
    public async Task Ports_ShowLinkPoeAndTheDevicesBehindThem()
    {
        await using var fake = RouterWithACamera();
        await using var client = await MikrotikClient.ConnectAsync(fake.Options("pass"));

        var ports = await MikrotikPorts.ReadAsync(client);

        Assert.Equal(new[] { "ether1", "ether2", "ether3", "ether4", "ether5", "sfp1" }, ports.Select(p => p.Name));
        var ether2 = ports.Single(p => p.Name == "ether2");
        Assert.True(ether2.LinkUp);
        Assert.Equal("100Mbps", ether2.Rate);
        Assert.Equal("bridge", ether2.Bridge);
        Assert.Equal("2026-10-25 11:06:13", ether2.LastLinkUp);
        Assert.Equal(3, ether2.LinkDowns);
        Assert.Equal("powered-on", ether2.Poe!.Status);
        Assert.Equal(3.4, ether2.Poe.PowerWatts);
        var camera = Assert.Single(ether2.Devices);
        Assert.Equal("D8:3A:DD:12:34:56", camera.Mac);
        Assert.Equal(new[] { "10.64.10.15", "192.168.88.250" }, camera.Addresses);
        Assert.Equal("ipcam", camera.HostName);

        var ether3 = ports.Single(p => p.Name == "ether3");
        Assert.False(ether3.LinkUp);
        Assert.Null(ether3.Rate);
        Assert.Equal("2026-10-25 10:31:02", ether3.LastLinkDown);
        Assert.Equal("waiting-for-load", ether3.Poe!.Status);
        Assert.Empty(ether3.Devices);

        var ether1 = ports.Single(p => p.Name == "ether1");
        Assert.Null(ether1.Poe);
        Assert.Null(ether1.Bridge);
    }

    [Fact]
    public async Task Ports_ASiteNetworkOnOnePort_IsCappedButCounted()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960(password: "pass");
        for (var i = 0; i < 8; i++)
            fake.AddRow("/interface/bridge/host", new() { ["mac-address"] = $"00:11:22:33:44:{i:X2}", ["on-interface"] = "ether1", ["bridge"] = "bridge" });
        await using var client = await MikrotikClient.ConnectAsync(fake.Options("pass"));

        var ether1 = (await MikrotikPorts.ReadAsync(client)).Single(p => p.Name == "ether1");

        Assert.Equal(MikrotikPorts.MaxDevicesPerPort, ether1.Devices.Count);
        Assert.Equal(8, ether1.DeviceCount);
    }

    [Fact]
    public async Task PowerCycle_AsksTheRouterToSwitchPoeOffAndOn()
    {
        await using var fake = RouterWithACamera();
        await using var client = await MikrotikClient.ConnectAsync(fake.Options("pass"));

        var done = await MikrotikPorts.PowerCycleAsync(client, "ether2", TimeSpan.FromSeconds(5));

        Assert.Equal(new[] { "ether2 5s" }, fake.PowerCycles);
        Assert.Contains("ether2", done);
    }

    [Fact]
    public async Task PowerCycle_PortWithoutPoe_IsRefused()
    {
        await using var fake = RouterWithACamera();
        await using var client = await MikrotikClient.ConnectAsync(fake.Options("pass"));

        var e = await Assert.ThrowsAsync<MikrotikException>(() => MikrotikPorts.PowerCycleAsync(client, "ether1", TimeSpan.FromSeconds(5)));

        Assert.Contains("no PoE", e.Message);
        Assert.Empty(fake.PowerCycles);
    }

    [Fact]
    public async Task PowerCycle_PoeSwitchedOff_IsRefused()
    {
        await using var fake = RouterWithACamera();
        fake.Tables["/interface/ethernet/poe"].Single(r => r["name"] == "ether4")["poe-out"] = "off";
        await using var client = await MikrotikClient.ConnectAsync(fake.Options("pass"));

        var e = await Assert.ThrowsAsync<MikrotikException>(() => MikrotikPorts.PowerCycleAsync(client, "ether4", TimeSpan.FromSeconds(5)));

        Assert.Contains("switched off", e.Message);
    }

    [Fact]
    public async Task RouterWithoutPoe_ShowsPortsWithoutIt()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960(password: "pass");
        fake.Tables.Remove("/interface/ethernet/poe");
        await using var client = await MikrotikClient.ConnectAsync(fake.Options("pass"));

        var ports = await MikrotikPorts.ReadAsync(client);

        Assert.All(ports, p => Assert.Null(p.Poe));
    }
}
