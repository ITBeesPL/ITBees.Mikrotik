using System.Net;
using ITBees.Mikrotik.Configuration;

namespace ITBees.Mikrotik.Tests;

public class ConfigurationTests
{
    [Fact]
    public void ParkingPackage_IsValid()
    {
        var result = TestData.ParkingPackage().Validate();
        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    [Fact]
    public void Defaults_RequireANewPassword()
    {
        var result = new MikrotikConfigurationPackage().Validate();
        Assert.Contains(result.Errors, e => e.Contains("AdminPassword"));

        var keep = new MikrotikConfigurationPackage { Security = { KeepCurrentPassword = true } }.Validate();
        Assert.True(keep.IsValid, string.Join("; ", keep.Errors));
        Assert.Contains(keep.Warnings, w => w.Contains("192.168.88.0/24"));
    }

    [Fact]
    public void Json_RoundTrips()
    {
        var package = TestData.ParkingPackage();
        package.Lte.Mode = LteMode.Modem;
        package.Lte.Apn = "internet";
        var json = package.ToJson();
        Assert.Contains("\"mode\": \"Modem\"", json);
        Assert.Contains("\"adminPassword\"", json);

        var back = MikrotikConfigurationPackage.FromJson(json);
        Assert.Equal(package.ToJson(), back.ToJson());
        Assert.Equal("10.64.12.20", back.Lan.Dhcp.StaticLeases[0].Address);
    }

    [Fact]
    public void FailoverCheckHost_MustNotBeADnsServer()
    {
        var package = TestData.ParkingPackage();
        package.Failover.CheckHosts = new() { "1.1.1.1" };
        Assert.Contains(package.Validate().Errors, e => e.Contains("also a DNS server"));
    }

    [Fact]
    public void Lan_MustNotOverlapHiLinkOrVpn()
    {
        var hiLink = TestData.ParkingPackage();
        hiLink.Lan.Address = "192.168.8.1/24";
        hiLink.Lan.Dhcp.StaticLeases.Clear();
        Assert.Contains(hiLink.Validate().Errors, e => e.Contains("HiLink"));

        var vpn = TestData.ParkingPackage();
        vpn.Lan.Address = "10.250.5.1/24";
        vpn.Lan.Dhcp.StaticLeases.Clear();
        Assert.Contains(vpn.Validate().Errors, e => e.Contains("overlaps the LAN"));
    }

    [Fact]
    public void Wan_CannotBeALanPort_AndApiCannotBeDisabled()
    {
        var package = TestData.ParkingPackage();
        package.Lan.Ports.Add("ether1");
        package.Security.DisabledServices.Add("api");
        var errors = package.Validate().Errors;
        Assert.Contains(errors, e => e.Contains("WAN interface ether1"));
        Assert.Contains(errors, e => e.Contains("'api'"));
    }

    [Fact]
    public void Vpn_RequiresKeysAndAddress()
    {
        var package = TestData.ParkingPackage();
        package.Vpn.ServerPublicKey = "nope";
        package.Vpn.Address = "10.250.0.12";
        package.Vpn.ServerEndpoint = "vpn.example:51820";
        var errors = package.Validate().Errors;
        Assert.Contains(errors, e => e.Contains("ServerPublicKey"));
        Assert.Contains(errors, e => e.Contains("Vpn.Address"));
        Assert.Contains(errors, e => e.Contains("ServerEndpoint"));
    }

    [Theory]
    [InlineData("10.64.12.1/24", "10.64.12.100", "10.64.12.250")]
    [InlineData("10.64.12.254/24", "10.64.12.100", "10.64.12.250")]
    [InlineData("10.0.0.1/28", "10.0.0.2", "10.0.0.14")]
    [InlineData("10.0.0.7/28", "10.0.0.8", "10.0.0.14")]
    public void DhcpPool_DefaultsSkipTheRouter(string lan, string start, string end)
    {
        var (s, e) = MikrotikConfigurationValidator.ResolvePool(new DhcpServerSettings(), Ipv4Prefix.Parse(lan));
        Assert.Equal(IPAddress.Parse(start), s);
        Assert.Equal(IPAddress.Parse(end), e);
    }

    [Fact]
    public void Ipv4Prefix_Math()
    {
        var lan = Ipv4Prefix.Parse("10.64.12.1/24");
        Assert.Equal("10.64.12.0/24", lan.NetworkCidr);
        Assert.Equal(IPAddress.Parse("10.64.12.255"), lan.Broadcast);
        Assert.True(lan.Contains(IPAddress.Parse("10.64.12.77")));
        Assert.False(lan.Contains(IPAddress.Parse("10.64.13.1")));
        Assert.True(Ipv4Prefix.Parse("10.250.0.0/16").Overlaps(Ipv4Prefix.Parse("10.250.7.0/24")));
        Assert.False(Ipv4Prefix.Parse("10.250.0.0/16").Overlaps(lan));
        Assert.False(Ipv4Prefix.TryParse("10.1", out _));
    }
}
