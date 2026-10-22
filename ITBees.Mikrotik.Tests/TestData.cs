using ITBees.Mikrotik.Configuration;
using ITBees.Mikrotik.WireGuard;

namespace ITBees.Mikrotik.Tests;

internal static class TestData
{
    public const string FactoryPassword = "STICKER123";
    public const string NewPassword = "Parking#2026!";

    public static readonly WireGuardKeyPair RouterKeys = WireGuardKeys.GenerateKeyPair();
    public static readonly WireGuardKeyPair HubKeys = WireGuardKeys.GenerateKeyPair();

    /// <summary>Typical parking package: own LAN 10.64.12.0/24, VPN to the hub, one barrier with a fixed address.</summary>
    public static MikrotikConfigurationPackage ParkingPackage(bool vpn = true) => new()
    {
        Identity = "octopark-test-p12",
        Security = { AdminPassword = NewPassword },
        Wan = { WaitForLeaseSeconds = 0 },
        Lan =
        {
            Address = "10.64.12.1/24",
            Dhcp = { StaticLeases = { new StaticLease { MacAddress = "00:11:22:33:44:55", Address = "10.64.12.20", Comment = "barrier entry" } } },
        },
        Vpn =
        {
            Enabled = vpn,
            Address = "10.250.0.12/16",
            ServerPublicKey = HubKeys.PublicKey,
            ServerEndpoint = "vpn.octopark.example",
            PrivateKey = RouterKeys.PrivateKey,
        },
    };
}
