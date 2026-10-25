using System.Globalization;
using System.Text.RegularExpressions;
using ITBees.Mikrotik.Api;

namespace ITBees.Mikrotik.Status;

/// <summary>A device the router sees behind a port: MAC from the bridge host table, IP from ARP / DHCP leases.</summary>
public sealed record MikrotikPortDevice(string Mac, IReadOnlyList<string> Addresses, string? HostName);

/// <summary>One Ethernet port of the router.</summary>
public sealed record MikrotikPortStatus(
    string Name,
    bool LinkUp,
    bool Disabled,
    string? Rate,
    string? Bridge,
    string? Comment,
    string? LastLinkUp,
    string? LastLinkDown,
    int? LinkDowns,
    MikrotikPoeStatus? Poe,
    IReadOnlyList<MikrotikPortDevice> Devices,
    int DeviceCount);

/// <summary>PoE output of a port (only ports that have one, e.g. ether2-ether5 of a hEX PoE).</summary>
public sealed record MikrotikPoeStatus(string? Mode, string? Status, double? PowerWatts);

/// <summary>
/// Ports of the router: link, speed, PoE and the devices learned on each port. RouterOS forgets a port's devices
/// when its link goes down (only the time of the last link change stays), so remembering them is up to the caller.
/// </summary>
public static class MikrotikPorts
{
    /// <summary>Most devices listed per port (the WAN port of a shared site network sees the whole site).</summary>
    public const int MaxDevicesPerPort = 5;

    public static async Task<IReadOnlyList<MikrotikPortStatus>> ReadAsync(IMikrotikClient client, CancellationToken cancellationToken = default)
    {
        var interfaces = (await client.PrintAsync("/interface").ConfigureAwait(false))
            .Where(r => r.Get("type") == "ether" && r.Get("name") is { Length: > 0 })
            .ToList();
        var bridgePorts = (await TryPrintAsync(client, "/interface/bridge/port").ConfigureAwait(false))
            .Where(r => r.Get("interface") != null)
            .GroupBy(r => r.Get("interface")!)
            .ToDictionary(g => g.Key, g => g.First().Get("bridge"));
        var hosts = (await TryPrintAsync(client, "/interface/bridge/host").ConfigureAwait(false))
            .Where(r => !IsTrue(r.Get("local")) && r.Get("mac-address") != null && r.Get("on-interface") != null)
            .GroupBy(r => r.Get("on-interface")!)
            .ToDictionary(g => g.Key, g => g.Select(r => r.Get("mac-address")!.ToUpperInvariant()).Distinct().ToList());
        var addresses = await ReadAddressesAsync(client).ConfigureAwait(false);
        var poe = (await TryPrintAsync(client, "/interface/ethernet/poe").ConfigureAwait(false))
            .Where(r => r.Get("name") != null)
            .ToDictionary(r => r.Get("name")!, r => r);

        var ports = new List<MikrotikPortStatus>();
        foreach (var row in interfaces.OrderBy(r => PortOrder(r.Get("name")!)))
        {
            var name = row.Get("name")!;
            var linkUp = IsTrue(row.Get("running"));
            var rate = linkUp ? await ReadRateAsync(client, name, cancellationToken).ConfigureAwait(false) : null;
            MikrotikPoeStatus? poeStatus = null;
            if (poe.TryGetValue(name, out var poeRow))
                poeStatus = await ReadPoeAsync(client, name, poeRow, cancellationToken).ConfigureAwait(false);

            var macs = hosts.TryGetValue(name, out var list) ? list : new List<string>();
            var devices = macs.Take(MaxDevicesPerPort).Select(mac => new MikrotikPortDevice(
                    mac,
                    addresses.TryGetValue(mac, out var known) ? known.Addresses : Array.Empty<string>(),
                    addresses.TryGetValue(mac, out var host) ? host.HostName : null))
                .ToList();
            ports.Add(new MikrotikPortStatus(
                name,
                linkUp,
                IsTrue(row.Get("disabled")),
                rate,
                bridgePorts.TryGetValue(name, out var bridge) ? bridge : null,
                row.Comment,
                row.Get("last-link-up-time"),
                row.Get("last-link-down-time"),
                int.TryParse(row.Get("link-downs"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var downs) ? downs : null,
                poeStatus,
                devices,
                macs.Count));
        }
        return ports;
    }

    /// <summary>
    /// Switches the port's PoE output off for <paramref name="duration"/> and back on (the router does both, so a lost
    /// session cannot leave the port unpowered): the camera behind it restarts.
    /// </summary>
    /// <exception cref="MikrotikException">The port has no PoE output, or it is switched off.</exception>
    public static async Task<string> PowerCycleAsync(IMikrotikClient client, string port, TimeSpan duration, CancellationToken cancellationToken = default)
    {
        var poe = (await TryPrintAsync(client, "/interface/ethernet/poe").ConfigureAwait(false)).FirstOrDefault(r => r.Get("name") == port)
                  ?? throw new MikrotikException(client.Host, $"{port} has no PoE output on this router.");
        if (poe.Get("poe-out") == "off")
            throw new MikrotikException(client.Host, $"PoE output of {port} is switched off (poe-out=off): nothing to restart.");

        var seconds = Math.Clamp((int)Math.Round(duration.TotalSeconds), 1, 60);
        // A refused command comes back as a trap and is thrown by the connection.
        await client.ExecuteAsync(
                new RouterOsCommand("/interface/ethernet/poe/power-cycle")
                    .With("numbers", port)
                    .With("duration", seconds.ToString(CultureInfo.InvariantCulture) + "s"),
                cancellationToken)
            .ConfigureAwait(false);
        return $"PoE power of {port} off for {seconds} s, then back on";
    }

    private static async Task<string?> ReadRateAsync(IMikrotikClient client, string name, CancellationToken cancellationToken)
    {
        var row = await MonitorOnceAsync(client, "/interface/ethernet/monitor", name, cancellationToken).ConfigureAwait(false);
        return row?.Get("rate");
    }

    private static async Task<MikrotikPoeStatus> ReadPoeAsync(IMikrotikClient client, string name, RouterOsRecord row, CancellationToken cancellationToken)
    {
        var monitor = await MonitorOnceAsync(client, "/interface/ethernet/poe/monitor", name, cancellationToken).ConfigureAwait(false);
        return new MikrotikPoeStatus(
            monitor?.Get("poe-out") ?? row.Get("poe-out"),
            monitor?.Get("poe-out-status") ?? row.Get("poe-out-status"),
            LeadingNumber(monitor?.Get("poe-out-power")));
    }

    private static async Task<RouterOsRecord?> MonitorOnceAsync(IMikrotikClient client, string command, string name, CancellationToken cancellationToken)
    {
        try
        {
            var response = await client.ExecuteAsync(new RouterOsCommand(command).With("numbers", name).With("once", string.Empty), cancellationToken).ConfigureAwait(false);
            return response.Records.FirstOrDefault();
        }
        catch (MikrotikException)
        {
            return null;
        }
    }

    private sealed record KnownAddress(List<string> Addresses, string? HostName);

    /// <summary>MAC -> IPv4 addresses (ARP first, then DHCP leases) and the DHCP host name.</summary>
    private static async Task<Dictionary<string, KnownAddress>> ReadAddressesAsync(IMikrotikClient client)
    {
        var known = new Dictionary<string, KnownAddress>(StringComparer.Ordinal);
        foreach (var row in await TryPrintAsync(client, "/ip/arp").ConfigureAwait(false))
        {
            var mac = row.Get("mac-address")?.ToUpperInvariant();
            var address = row.Get("address");
            if (mac == null || address == null || row.Get("status") == "failed" || mac == "00:00:00:00:00:00")
                continue;
            Add(known, mac, address, null);
        }
        foreach (var row in await TryPrintAsync(client, "/ip/dhcp-server/lease").ConfigureAwait(false))
        {
            var mac = row.Get("mac-address")?.ToUpperInvariant();
            if (mac == null)
                continue;
            Add(known, mac, row.Get("address"), row.Get("host-name"));
        }
        return known;
    }

    private static void Add(Dictionary<string, KnownAddress> known, string mac, string? address, string? hostName)
    {
        if (!known.TryGetValue(mac, out var entry))
            known[mac] = entry = new KnownAddress(new List<string>(), hostName);
        else if (entry.HostName == null && hostName != null)
            known[mac] = entry = entry with { HostName = hostName };
        if (address != null && !entry.Addresses.Contains(address))
            entry.Addresses.Add(address);
    }

    private static async Task<IReadOnlyList<RouterOsRecord>> TryPrintAsync(IMikrotikClient client, string menu)
    {
        try
        {
            return await client.PrintAsync(menu).ConfigureAwait(false);
        }
        catch (MikrotikException)
        {
            // Menu missing on this router (e.g. no PoE, no DHCP server package).
            return Array.Empty<RouterOsRecord>();
        }
    }

    private static bool IsTrue(string? value) => value is "true" or "yes";

    /// <summary>ether2 before ether10, sfp after ether.</summary>
    private static (int, int, string) PortOrder(string name)
    {
        var match = Regex.Match(name, @"^(\D*)(\d+)");
        return match.Success
            ? (match.Groups[1].Value == "ether" ? 0 : 1, int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture), name)
            : (2, 0, name);
    }

    private static double? LeadingNumber(string? value)
    {
        if (value == null)
            return null;
        var match = Regex.Match(value, @"^\d+(\.\d+)?");
        return match.Success ? double.Parse(match.Value, CultureInfo.InvariantCulture) : null;
    }
}
