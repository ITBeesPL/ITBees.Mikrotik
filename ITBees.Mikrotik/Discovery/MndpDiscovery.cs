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

    /// <summary>Also discover over IPv6 (RouterOS 7 answers on ff02::1; works regardless of IPv4 addressing).</summary>
    public bool UseIpv6 { get; set; } = true;
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
        using var listening = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        listening.CancelAfter(options.Duration);

        var sockets = new List<(Socket Socket, bool IsIpv6)>();
        try
        {
            sockets.Add((OpenSocket(AddressFamily.InterNetwork, options.ListenPort), false));
            if (options.UseIpv6 && Socket.OSSupportsIPv6)
            {
                try
                {
                    sockets.Add((OpenSocket(AddressFamily.InterNetworkV6, options.ListenPort), true));
                }
                catch (SocketException e)
                {
                    _logger.LogDebug("IPv6 MNDP socket unavailable: {Message}", e.Message);
                }
            }

            var receivers = sockets.Select(s => ReceiveLoopAsync(s.Socket, s.IsIpv6, neighbors, listening.Token)).ToList();
            var sender = SendLoopAsync(sockets, options, listening.Token);
            await Task.WhenAll(receivers.Append(sender)).ConfigureAwait(false);
        }
        finally
        {
            foreach (var (socket, _) in sockets)
                socket.Dispose();
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

    private async Task SendLoopAsync(List<(Socket Socket, bool IsIpv6)> sockets, MndpDiscoveryOptions options, CancellationToken cancellationToken)
    {
        var v4 = sockets.FirstOrDefault(s => !s.IsIpv6).Socket;
        var v6 = sockets.FirstOrDefault(s => s.IsIpv6).Socket;
        var targets = options.TargetAddresses ?? BuildDefaultTargets(v6 != null);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                foreach (var target in targets)
                {
                    var socket = target.AddressFamily == AddressFamily.InterNetworkV6 ? v6 : v4;
                    if (socket == null)
                        continue;
                    try
                    {
                        await socket.SendToAsync(MndpPacket.DiscoveryRequest, SocketFlags.None, new IPEndPoint(target, options.TargetPort), cancellationToken).ConfigureAwait(false);
                    }
                    catch (SocketException e)
                    {
                        _logger.LogDebug("MNDP request to {Target} failed: {Message}", target, e.Message);
                    }
                }
                await Task.Delay(options.RequestInterval, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task ReceiveLoopAsync(Socket socket, bool isIpv6, ConcurrentDictionary<string, MikrotikNeighbor> neighbors, CancellationToken cancellationToken)
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

            var key = neighbor.MacAddressText;
            var isNew = false;
            neighbors.AddOrUpdate(
                key,
                _ =>
                {
                    isNew = true;
                    return neighbor;
                },
                (_, existing) => Merge(existing, neighbor));
            if (isNew)
            {
                _logger.LogDebug("MNDP: {Neighbor}", neighbor);
                NeighborFound?.Invoke(this, neighbor);
            }
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
