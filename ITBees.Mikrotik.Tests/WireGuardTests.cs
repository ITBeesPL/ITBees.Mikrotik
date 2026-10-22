using ITBees.Mikrotik.WireGuard;

namespace ITBees.Mikrotik.Tests;

public class WireGuardTests
{
    [Fact]
    public void X25519_MatchesRfc7748Vector()
    {
        var scalar = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        var u = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        var result = WireGuardKeys.ScalarMult(scalar, u);
        Assert.Equal("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", Convert.ToHexString(result).ToLowerInvariant());
    }

    [Fact]
    public void PublicKeys_AndSharedSecret_MatchRfc7748DiffieHellmanVector()
    {
        var alicePrivate = Convert.ToBase64String(Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        var bobPrivate = Convert.ToBase64String(Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));

        var alicePublic = WireGuardKeys.GetPublicKey(alicePrivate);
        var bobPublic = WireGuardKeys.GetPublicKey(bobPrivate);
        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Hex(alicePublic));
        Assert.Equal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Hex(bobPublic));

        var shared1 = WireGuardKeys.ScalarMult(Convert.FromBase64String(alicePrivate), Convert.FromBase64String(bobPublic));
        var shared2 = WireGuardKeys.ScalarMult(Convert.FromBase64String(bobPrivate), Convert.FromBase64String(alicePublic));
        Assert.Equal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", Convert.ToHexString(shared1).ToLowerInvariant());
        Assert.Equal(shared1, shared2);
    }

    [Fact]
    public void GeneratedKeys_AreValidAndClamped()
    {
        var pair = WireGuardKeys.GenerateKeyPair();
        Assert.True(WireGuardKeys.IsValidKey(pair.PrivateKey));
        Assert.True(WireGuardKeys.IsValidKey(pair.PublicKey));
        Assert.Equal(44, pair.PrivateKey.Length);
        var raw = Convert.FromBase64String(pair.PrivateKey);
        Assert.Equal(0, raw[0] & 7);
        Assert.Equal(64, raw[31] & 0xC0);
        Assert.Equal(pair.PublicKey, WireGuardKeys.GetPublicKey(pair.PrivateKey));
        Assert.False(WireGuardKeys.IsValidKey("not-a-key"));
    }

    [Fact]
    public void HubPeer_RendersWgQuickSection()
    {
        var peer = new WireGuardHubPeer("octopark-p12", "PUBKEY=", "PSK=", new[] { "10.250.0.12/32", "10.64.12.0/24" });
        var text = peer.ToWgQuickSection();
        Assert.Contains("PublicKey = PUBKEY=", text);
        Assert.Contains("PresharedKey = PSK=", text);
        Assert.Contains("AllowedIPs = 10.250.0.12/32, 10.64.12.0/24", text);
    }

    private static string Hex(string base64) => Convert.ToHexString(Convert.FromBase64String(base64)).ToLowerInvariant();
}
