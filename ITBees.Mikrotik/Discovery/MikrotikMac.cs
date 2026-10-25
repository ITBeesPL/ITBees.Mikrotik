using System.Net.NetworkInformation;

namespace ITBees.Mikrotik.Discovery;

/// <summary>
/// Telling whether a MAC belongs to a given router. RouterOS announces every bridge port with that port's own MAC
/// (a column on ether3 hears ether3's MAC, not the bridge's), and a RouterBOARD's interface MACs are consecutive,
/// starting with ether1 - the MAC printed on the label.
/// </summary>
public static class MikrotikMac
{
    /// <summary>How far apart two MACs of one router can be (RB5009: 8 ethernet ports + SFP, wireless models a few more).</summary>
    public const int MaxPortSpread = 16;

    /// <summary>
    /// True when <paramref name="candidate"/> may be another interface of the router with <paramref name="known"/>
    /// (same vendor prefix, at most <see cref="MaxPortSpread"/> apart). A hint only: confirm with
    /// <see cref="ReadRouterMacsAsync"/> after logging in.
    /// </summary>
    public static bool IsNear(PhysicalAddress known, PhysicalAddress candidate, int maxDistance = MaxPortSpread)
    {
        var a = ToNumber(known);
        var b = ToNumber(candidate);
        if (a == null || b == null)
            return false;
        if (a.Value >> 24 != b.Value >> 24)
            return false;
        return Math.Abs(a.Value - b.Value) <= maxDistance;
    }

    /// <summary>
    /// Every MAC of the logged-in router: all interfaces (ports, bridge, wireless) plus the factory MACs of the
    /// ethernet ports (orig-mac-address), in "4C:5E:0C:11:22:33" form.
    /// </summary>
    public static async Task<IReadOnlySet<string>> ReadRouterMacsAsync(IMikrotikClient client)
    {
        var macs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in await client.PrintAsync("/interface").ConfigureAwait(false))
            Add(macs, row.Get("mac-address"));
        try
        {
            foreach (var row in await client.PrintAsync("/interface/ethernet").ConfigureAwait(false))
            {
                Add(macs, row.Get("orig-mac-address"));
                Add(macs, row.Get("mac-address"));
            }
        }
        catch (MikrotikException)
        {
            // Not every router has the menu (CHR); /interface already listed the current MACs.
        }
        return macs;
    }

    /// <summary>"4C:5E:0C:11:22:33" for any common spelling; null when it is not a MAC.</summary>
    public static string? Normalize(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
            return null;
        try
        {
            return MikrotikNeighbor.FormatMac(LinkLocal.ParseMac(mac));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static void Add(HashSet<string> macs, string? mac)
    {
        if (Normalize(mac) is { } normalized && normalized != "00:00:00:00:00:00")
            macs.Add(normalized);
    }

    private static long? ToNumber(PhysicalAddress mac)
    {
        var bytes = mac.GetAddressBytes();
        if (bytes.Length != 6)
            return null;
        long value = 0;
        foreach (var b in bytes)
            value = value << 8 | b;
        return value;
    }
}
