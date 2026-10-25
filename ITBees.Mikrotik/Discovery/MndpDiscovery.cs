using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ITBees.Mikrotik.Discovery;

public sealed class MndpDiscoveryOptions
{
    /// <summary>How long to listen. Routers answer requests at once and also announce themselves periodically.</summary>
    public TimeSpan Duration { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>How often the discovery request is repeated while listening (UDP may get lost).</summary>
    public TimeSpan RequestInterval { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Local port; 5678 receives broadcast answers and periodic announcements. 0 = any free port.</summary>
    public int ListenPort { get; set; } = MndpPacket.Port;

    /// <summary>Port the requests are sent to.</summary>
    public int TargetPort { get; set; } = MndpPacket.Port;

    /// <summary>
    /// Where to send requests. Null (default) = 255.255.255.255, the directed broadcast of every local IPv4
    /// subnet and the IPv6 all-nodes multicast (ff02::1) on every interface.
    /// </summary>
    public IReadOnlyList<IPAddress>? TargetAddresses { get; set; }

    /// <summary>
    /// Also discover over IPv6: routers announce themselves on ff02::1 regardless of IPv4 addressing. RouterOS 7.21
    /// did not answer IPv6 requests in tests, so on an IPv4-less segment it is heard only in its periodic announcements.
    /// </summary>
    public bool UseIpv6 { get; set; } = true;

    /// <summary>
    /// Also send IPv4 requests out of every interface that has no IPv4 address (Linux; needs kernel 5.7+ or
    /// CAP_NET_RAW, otherwise skipped). A request to 255.255.255.255 leaves only through the default route's
    /// interface (e.g. Wi-Fi), so a router on a cable without IPv4 would never hear it.
    /// </summary>
    public bool UseInterfacesWithoutIpv4 { get; set; } = true;

    /// <summary>
    /// When set, listening goes on after <see cref="Duration"/> until a router matching this predicate is seen or
    /// <see cref="MaxDuration"/> passes. A router that answers no request on our segment is still found in its
    /// periodic announcement (every ~20-30 s).
    /// </summary>
    public Func<MikrotikNeighbor, bool>? WaitFor { get; set; }

    /// <summary>Longest listening time when <see cref="WaitFor"/> is set.</summary>
    public TimeSpan MaxDuration { get; set; } = TimeSpan.FromSeconds(35);
}

/// <summary>
/// Lists MikroTik routers on the local segments using MNDP, like Winbox's "Neighbors" tab. Works at layer 2
/// (broadcast / link-local multicast), so routers are found even when their IP addresses are in a different
/// subnet than this computer. RouterOS only answers on interfaces from its discovery interface list
/// (factory default: LAN ports), so connect the computer to ether2-ether5 of a factory-new RB960PGS.
/// </summary>
public sealed class MndpDiscovery
{
    private static readonly IPAddress AllNodes = IPAddress.Parse("ff02::1");
    private readonly ILogger _logger;

    public MndpDiscovery(ILogger<MndpDiscovery>? logger = null)
    {
        _logger = (ILogger?)logger ?? NullLogger.Instance;
    }

    /// <summary>Raised for every router the first time it is seen during a discovery run.</summary>
    public event EventHandler<MikrotikNeighbor>? NeighborFound;

    public async Task<IReadOnlyList<MikrotikNeighbor>> DiscoverAsync(MndpDiscoveryOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new MndpDiscoveryOptions();
        var neighbors = new ConcurrentDictionary<string, MikrotikNeighbor>(StringComparer.Ordinal);
        var matched = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var listening = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var sockets = new List<MndpSocket>();
        try
        {
            sockets.Add(new MndpSocket(OpenSocket(AddressFamily.InterNetwork, options.ListenPort), false, null));
            if (options.UseIpv6 && Socket.OSSupportsIPv6)
            {
                try
                {
                    sockets.Add(new MndpSocket(OpenSocket(AddressFamily.InterNetworkV6, options.ListenPort), true, null));
                }
                catch (SocketException e)
                {
                    _logger.LogDebug("IPv6 MNDP socket unavailable: {Message}", e.Message);
                }
            }
            if (options.UseInterfacesWithoutIpv4 && options.TargetAddresses == null && OperatingSystem.IsLinux())
            {
                foreach (var device in InterfacesWithoutIpv4())
                {
                    var socket = TryOpenDeviceSocket(device, options.ListenPort);
                    if (socket != null)
                        sockets.Add(new MndpSocket(socket, false, device));
                }
            }

            var receivers = sockets.Select(s => ReceiveLoopAsync(s.Socket, s.IsIpv6, neighbors, options.WaitFor, matched, listening.Token)).ToList();
            var sender = SendLoopAsync(sockets, options, listening.Token);
            var stopper = StopListeningAsync(options, matched.Task, listening);
            await Task.WhenAll(receivers.Append(sender).Append(stopper)).ConfigureAwait(false);
        }
        finally
        {
            foreach (var s in sockets)
                s.Socket.Dispose();
        }

        cancellationToken.ThrowIfCancellationRequested();
        return neighbors.Values
            .OrderBy(n => n.Identity ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .ThenBy(n => n.MacAddressText, StringComparer.Ordinal)
            .ToArray();
    }

    private Socket OpenSocket(AddressFamily family, int port)
    {
        var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            if (family == AddressFamily.InterNetwork)
            {
                socket.EnableBroadcast = true;
                TrySetOption(() => socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true));
            }
            else
            {
                socket.DualMode = false;
                TrySetOption(() => socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.PacketInformation, true));
            }

            var any = family == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any;
            try
            {
                socket.Bind(new IPEndPoint(any, port));
            }
            catch (SocketException e) when (port != 0 && e.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                // Another program (e.g. Winbox) holds the port exclusively: still send requests and read direct answers.
                _logger.LogWarning("UDP port {Port} is in use ({Message}); listening on a random port, periodic announcements will be missed.", port, e.Message);
                socket.Bind(new IPEndPoint(any, 0));
            }
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>A listening socket; <see cref="Device"/> is set for the IPv4 sockets bound to an interface without IPv4.</summary>
    private sealed record MndpSocket(Socket Socket, bool IsIpv6, string? Device);

    // A router answering late often sends its IPv4 and IPv6 packets together: give the second one a moment.
    private static readonly TimeSpan MatchGrace = TimeSpan.FromMilliseconds(300);

    private static async Task StopListeningAsync(MndpDiscoveryOptions options, Task matched, CancellationTokenSource listening)
    {
        try
        {
            await Task.Delay(options.Duration, listening.Token).ConfigureAwait(false);
            var extra = options.MaxDuration - options.Duration;
            if (options.WaitFor != null && !matched.IsCompleted && extra > TimeSpan.Zero)
            {
                await Task.WhenAny(matched, Task.Delay(extra, listening.Token)).ConfigureAwait(false);
                if (matched.IsCompleted)
                    await Task.Delay(MatchGrace, listening.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        listening.Cancel();
    }

    private async Task SendLoopAsync(List<MndpSocket> sockets, MndpDiscoveryOptions options, CancellationToken cancellationToken)
    {
        var v4 = sockets.FirstOrDefault(s => !s.IsIpv6 && s.Device == null)?.Socket;
        var v6 = sockets.FirstOrDefault(s => s.IsIpv6)?.Socket;
        var targets = options.TargetAddresses ?? BuildDefaultTargets(v6 != null);
        var deviceSockets = sockets.Where(s => s.Device != null).ToList();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                foreach (var target in targets)
                {
                    var socket = target.AddressFamily == AddressFamily.InterNetworkV6 ? v6 : v4;
                    if (socket != null)
                        await SendRequestAsync(socket, new IPEndPoint(target, options.TargetPort), null, cancellationToken).ConfigureAwait(false);
                }
                foreach (var device in deviceSockets)
                    await SendRequestAsync(device.Socket, new IPEndPoint(IPAddress.Broadcast, options.TargetPort), device.Device, cancellationToken).ConfigureAwait(false);
                await Task.Delay(options.RequestInterval, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task SendRequestAsync(Socket socket, IPEndPoint target, string? device, CancellationToken cancellationToken)
    {
        try
        {
            await socket.SendToAsync(MndpPacket.DiscoveryRequest, SocketFlags.None, target, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException e)
        {
            _logger.LogDebug("MNDP request to {Target}{Device} failed: {Message}", target, device == null ? string.Empty : " via " + device, e.Message);
        }
    }

    // Linux socket option numbers (generic architectures: x86, ARM).
    private const int SolSocket = 1;
    private const int SoBindToDevice = 25;
    private const int IffBroadcast = 0x2;

    /// <summary>
    /// An IPv4 socket that sends through one interface only (SO_BINDTODEVICE): the kernel sends a broadcast through
    /// it even without an IPv4 address on that interface. Null when the kernel refuses (before 5.7 without CAP_NET_RAW).
    /// </summary>
    private Socket? TryOpenDeviceSocket(string device, int port)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.EnableBroadcast = true;
            TrySetOption(() => socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true));
            socket.SetRawSocketOption(SolSocket, SoBindToDevice, System.Text.Encoding.ASCII.GetBytes(device + "\0"));
            try
            {
                socket.Bind(new IPEndPoint(IPAddress.Any, port));
            }
            catch (SocketException e) when (port != 0 && e.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                socket.Bind(new IPEndPoint(IPAddress.Any, 0));
            }
            _logger.LogDebug("MNDP: also sending IPv4 requests out of {Device} (no IPv4 address there).", device);
            return socket;
        }
        catch (Exception e) when (e is SocketException or PlatformNotSupportedException)
        {
            _logger.LogDebug("MNDP: cannot send IPv4 requests out of {Device}: {Message}", device, e.Message);
            socket.Dispose();
            return null;
        }
    }

    /// <summary>Up, broadcast-capable interfaces (cables, Wi-Fi; not tunnels or CAN) without an IPv4 address.</summary>
    private IEnumerable<string> InterfacesWithoutIpv4()
    {
        var names = new List<string>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp)
                    continue;
                if (nic.GetIPProperties().UnicastAddresses.Any(u => u.Address.AddressFamily == AddressFamily.InterNetwork))
                    continue;
                if (HasBroadcastFlag(nic.Name))
                    names.Add(nic.Name);
            }
        }
        catch (NetworkInformationException e)
        {
            _logger.LogDebug("Cannot enumerate network interfaces: {Message}", e.Message);
        }
        return names;
    }

    private static bool HasBroadcastFlag(string device)
    {
        try
        {
            var text = File.ReadAllText($"/sys/class/net/{device}/flags").Trim();
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                text = text[2..];
            return int.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out var flags) && (flags & IffBroadcast) != 0;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task ReceiveLoopAsync(
        Socket socket, bool isIpv6, ConcurrentDictionary<string, MikrotikNeighbor> neighbors,
        Func<MikrotikNeighbor, bool>? waitFor, TaskCompletionSource matched, CancellationToken cancellationToken)
    {
        var buffer = new byte[2048];
        EndPoint any = new IPEndPoint(isIpv6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveMessageFromResult result;
            try
            {
                result = await socket.ReceiveMessageFromAsync(buffer, SocketFlags.None, any, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize or SocketError.NetworkReset)
            {
                continue;
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            if (!MndpPacket.TryParse(buffer.AsSpan(0, result.ReceivedBytes), out var packet) || packet?.MacAddress == null)
                continue;

            var source = (result.RemoteEndPoint as IPEndPoint)?.Address;
            var interfaceIndex = result.PacketInformation.Interface;
            if (interfaceIndex <= 0 && source is { IsIPv6LinkLocal: true })
                interfaceIndex = (int)source.ScopeId;

            var neighbor = new MikrotikNeighbor
            {
                MacAddress = packet.MacAddress,
                Identity = packet.Identity,
                Version = packet.Version,
                Platform = packet.Platform,
                Board = packet.Board,
                SoftwareId = packet.SoftwareId,
                Uptime = packet.Uptime,
                RouterInterface = packet.InterfaceName,
                Ipv4Address = packet.Ipv4Address,
                Ipv6Address = packet.Ipv6Address,
                SourceAddress = source,
                LocalInterfaceIndex = interfaceIndex,
                LocalInterfaceName = LocalSubnets.InterfaceName(interfaceIndex),
                LastSeen = DateTimeOffset.Now,
            };

            // Several sockets can receive the same broadcast at once: TryAdd decides which one reports it.
            var key = neighbor.MacAddressText;
            MikrotikNeighbor stored;
            if (neighbors.TryAdd(key, neighbor))
            {
                stored = neighbor;
                _logger.LogDebug("MNDP: {Neighbor}", neighbor);
                NeighborFound?.Invoke(this, neighbor);
            }
            else
            {
                stored = neighbors.AddOrUpdate(key, neighbor, (_, existing) => Merge(existing, neighbor));
            }
            if (waitFor != null && !matched.Task.IsCompleted && waitFor(stored))
                matched.TrySetResult();
        }
    }

    private static MikrotikNeighbor Merge(MikrotikNeighbor existing, MikrotikNeighbor update) => existing with
    {
        Identity = update.Identity ?? existing.Identity,
        Version = update.Version ?? existing.Version,
        Platform = update.Platform ?? existing.Platform,
        Board = update.Board ?? existing.Board,
        SoftwareId = update.SoftwareId ?? existing.SoftwareId,
        Uptime = update.Uptime ?? existing.Uptime,
        RouterInterface = update.RouterInterface ?? existing.RouterInterface,
        Ipv4Address = update.Ipv4Address ?? existing.Ipv4Address,
        Ipv6Address = update.Ipv6Address ?? existing.Ipv6Address,
        SourceAddress = existing.SourceAddress?.AddressFamily == AddressFamily.InterNetwork ? existing.SourceAddress : update.SourceAddress ?? existing.SourceAddress,
        LocalInterfaceIndex = existing.LocalInterfaceIndex > 0 ? existing.LocalInterfaceIndex : update.LocalInterfaceIndex,
        LocalInterfaceName = existing.LocalInterfaceName ?? update.LocalInterfaceName,
        LastSeen = update.LastSeen,
    };

    private List<IPAddress> BuildDefaultTargets(bool includeIpv6)
    {
        var targets = new List<IPAddress> { IPAddress.Broadcast };
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;
                var properties = nic.GetIPProperties();
                foreach (var unicast in properties.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily == AddressFamily.InterNetwork && unicast.PrefixLength is > 0 and < 31)
                    {
                        var broadcast = Configuration.Ipv4Prefix.BroadcastOf(unicast.Address, unicast.PrefixLength);
                        if (!targets.Contains(broadcast))
                            targets.Add(broadcast);
                    }
                }
                if (includeIpv6 && nic.Supports(NetworkInterfaceComponent.IPv6) && nic.SupportsMulticast)
                {
                    var index = TryGetIpv6Index(properties);
                    if (index > 0)
                        targets.Add(new IPAddress(AllNodes.GetAddressBytes(), index));
                }
            }
        }
        catch (NetworkInformationException e)
        {
            _logger.LogDebug("Cannot enumerate network interfaces: {Message}", e.Message);
        }
        return targets;
    }

    private static int TryGetIpv6Index(IPInterfaceProperties properties)
    {
        try
        {
            return properties.GetIPv6Properties()?.Index ?? 0;
        }
        catch (Exception e) when (e is NetworkInformationException or PlatformNotSupportedException)
        {
            return 0;
        }
    }

    private void TrySetOption(Action action)
    {
        try
        {
            action();
        }
        catch (Exception e) when (e is SocketException or PlatformNotSupportedException)
        {
            _logger.LogDebug("Socket option not supported: {Message}", e.Message);
        }
    }
}
