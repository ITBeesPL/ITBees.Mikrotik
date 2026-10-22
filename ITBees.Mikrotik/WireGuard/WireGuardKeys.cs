using System.Numerics;
using System.Security.Cryptography;

namespace ITBees.Mikrotik.WireGuard;

/// <summary>A WireGuard key pair in the base64 form used by wg, wg-quick and RouterOS.</summary>
public sealed record WireGuardKeyPair(string PrivateKey, string PublicKey);

/// <summary>
/// WireGuard (Curve25519 / X25519, RFC 7748) key helpers, so the backend can prepare keys before a router
/// is installed and register the peer on the VPN hub in advance. .NET 8 has no portable X25519, hence the
/// small implementation below. It is not constant-time: use it for key generation, not as a VPN data path.
/// </summary>
public static class WireGuardKeys
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger A24 = 121665;

    public static WireGuardKeyPair GenerateKeyPair()
    {
        var privateKey = GeneratePrivateKey();
        return new WireGuardKeyPair(privateKey, GetPublicKey(privateKey));
    }

    /// <summary>Random clamped Curve25519 private key (same as `wg genkey`).</summary>
    public static string GeneratePrivateKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        Clamp(key);
        return Convert.ToBase64String(key);
    }

    /// <summary>Random 32-byte preshared key (same as `wg genpsk`).</summary>
    public static string GeneratePresharedKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    /// <summary>Public key of a base64 private key (same as `wg pubkey`).</summary>
    public static string GetPublicKey(string privateKey)
    {
        var scalar = DecodeKey(privateKey, nameof(privateKey));
        var basePoint = new byte[32];
        basePoint[0] = 9;
        return Convert.ToBase64String(ScalarMult(scalar, basePoint));
    }

    /// <summary>True for a base64 string of exactly 32 bytes.</summary>
    public static bool IsValidKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return false;
        Span<byte> buffer = stackalloc byte[33];
        return Convert.TryFromBase64String(key.Trim(), buffer, out var written) && written == 32;
    }

    /// <summary>X25519(k, u) from RFC 7748 section 5; inputs and output are 32-byte little-endian strings.</summary>
    public static byte[] ScalarMult(byte[] scalar, byte[] uCoordinate)
    {
        if (scalar.Length != 32 || uCoordinate.Length != 32)
            throw new ArgumentException("X25519 inputs are 32 bytes.");

        var k = (byte[])scalar.Clone();
        Clamp(k);
        var kInt = ToBigInteger(k);
        var u = (byte[])uCoordinate.Clone();
        u[31] &= 0x7F;
        var x1 = ToBigInteger(u) % P;

        BigInteger x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        var swap = 0;
        for (var t = 254; t >= 0; t--)
        {
            var kt = (int)((kInt >> t) & 1);
            swap ^= kt;
            ConditionalSwap(swap, ref x2, ref x3);
            ConditionalSwap(swap, ref z2, ref z3);
            swap = kt;

            var a = Mod(x2 + z2);
            var aa = Mod(a * a);
            var b = Mod(x2 - z2);
            var bb = Mod(b * b);
            var e = Mod(aa - bb);
            var c = Mod(x3 + z3);
            var d = Mod(x3 - z3);
            var da = Mod(d * a);
            var cb = Mod(c * b);
            x3 = Mod((da + cb) * (da + cb));
            z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
            x2 = Mod(aa * bb);
            z2 = Mod(e * (aa + A24 * e));
        }
        ConditionalSwap(swap, ref x2, ref x3);
        ConditionalSwap(swap, ref z2, ref z3);

        var result = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
        return ToLittleEndian32(result);
    }

    private static void Clamp(byte[] key)
    {
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
    }

    private static byte[] DecodeKey(string key, string parameterName)
    {
        if (!IsValidKey(key))
            throw new ArgumentException("A WireGuard key is 32 bytes encoded as base64 (44 characters).", parameterName);
        return Convert.FromBase64String(key.Trim());
    }

    private static void ConditionalSwap(int swap, ref BigInteger a, ref BigInteger b)
    {
        if (swap == 1)
            (a, b) = (b, a);
    }

    private static BigInteger Mod(BigInteger value)
    {
        var r = value % P;
        return r.Sign < 0 ? r + P : r;
    }

    private static BigInteger ToBigInteger(byte[] littleEndian) => new(littleEndian, isUnsigned: true, isBigEndian: false);

    private static byte[] ToLittleEndian32(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        var result = new byte[32];
        Array.Copy(bytes, result, Math.Min(32, bytes.Length));
        return result;
    }
}
