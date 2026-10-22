using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ITBees.Mikrotik.Discovery;

public sealed record MikrotikCredentials(string Username, string Password)
{
    public override string ToString() => $"{Username}/***";
}

public enum MikrotikLoginOutcome
{
    Success,

    /// <summary>The router answered and rejected the credentials.</summary>
    AuthenticationFailed,

    /// <summary>Credentials accepted but the password must be changed first (e.g. in Winbox).</summary>
    PasswordExpired,

    /// <summary>No API connection on this address (timeout, refused, no route).</summary>
    Unreachable,

    Error,
}

/// <summary>One try of one credential pair on one address of one router.</summary>
public sealed record MikrotikLoginAttempt(MikrotikNeighbor Device, string? Address, string? Username, MikrotikLoginOutcome Outcome, string? Message)
{
    public override string ToString() =>
        $"{Device.MacAddressText} {Device.Identity} {Address ?? "-"} {Username ?? "-"}: {Outcome}{(Message != null ? " - " + Message : string.Empty)}";
}

public sealed class MikrotikLoginScanOptions
{
    /// <summary>Credential pairs tried in order on each router, e.g. the standard parking password first, then the sticker password.</summary>
    public IList<MikrotikCredentials> Credentials { get; set; } = new List<MikrotikCredentials>();

    /// <summary>Optional filter, e.g. only RB960PGS or a known MAC.</summary>
    public Func<MikrotikNeighbor, bool>? Filter { get; set; }

    public int MaxParallelism { get; set; } = 4;

    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(3);

    public TimeSpan CommandTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public int? Port { get; set; }

    public bool UseTls { get; set; }
}

public sealed class MikrotikLoginScanResult
{
    public MikrotikLoginScanResult(MikrotikClient client, MikrotikNeighbor device, MikrotikCredentials credentials, IReadOnlyList<MikrotikLoginAttempt> attempts)
    {
        Client = client;
        Device = device;
        Credentials = credentials;
        Attempts = attempts;
    }

    /// <summary>The logged-in session. The caller owns it and must dispose it.</summary>
    public MikrotikClient Client { get; }

    public MikrotikNeighbor Device { get; }

    /// <summary>The credential pair that worked.</summary>
    public MikrotikCredentials Credentials { get; }

    public IReadOnlyList<MikrotikLoginAttempt> Attempts { get; }
}

/// <summary>
/// Tries the given credentials on every discovered router until one accepts them. With per-device factory
/// passwords (sticker) this identifies "the router whose sticker I am holding" among several on the network.
/// </summary>
public sealed class MikrotikLoginScanner
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;

    public MikrotikLoginScanner(ILoggerFactory? loggerFactory = null)
    {
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
        _logger = _loggerFactory.CreateLogger<MikrotikLoginScanner>();
    }

    /// <exception cref="MikrotikDeviceNotFoundException">No router accepted any of the credentials; see Attempts.</exception>
    public async Task<MikrotikLoginScanResult> FindAsync(IEnumerable<MikrotikNeighbor> neighbors, MikrotikLoginScanOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(neighbors);
        ArgumentNullException.ThrowIfNull(options);
        if (options.Credentials.Count == 0)
            throw new ArgumentException("At least one credential pair is required.", nameof(options));

        var candidates = neighbors.Where(n => options.Filter?.Invoke(n) ?? true).ToList();
        var attempts = new ConcurrentQueue<MikrotikLoginAttempt>();
        if (candidates.Count == 0)
            throw new MikrotikDeviceNotFoundException("No MikroTik router was found on the network (or none matched the filter). Connect this computer to a LAN port (ether2-ether5) of the router.", Array.Empty<MikrotikLoginAttempt>());

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var throttle = new SemaphoreSlim(Math.Max(1, options.MaxParallelism));
        var winner = new TaskCompletionSource<(MikrotikClient Client, MikrotikNeighbor Device, MikrotikCredentials Credentials)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var losers = new ConcurrentBag<MikrotikClient>();

        var tasks = candidates.Select(async neighbor =>
        {
            try
            {
                await throttle.WaitAsync(stop.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            try
            {
                var found = await TryDeviceAsync(neighbor, options, attempts, stop.Token).ConfigureAwait(false);
                if (found == null)
                    return;
                if (winner.TrySetResult((found.Value.Client, neighbor, found.Value.Credentials)))
                    stop.Cancel();
                else
                    losers.Add(found.Value.Client);
            }
            finally
            {
                throttle.Release();
            }
        }).ToList();

        await Task.WhenAll(tasks).ConfigureAwait(false);
        foreach (var extra in losers)
            await extra.DisposeAsync().ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        var list = attempts.ToArray();
        if (winner.Task.IsCompletedSuccessfully)
        {
            var (client, device, credentials) = winner.Task.Result;
            _logger.LogInformation("Logged in to {Device} as {User}", device, credentials.Username);
            return new MikrotikLoginScanResult(client, device, credentials, list);
        }

        var reachable = list.Count(a => a.Outcome is MikrotikLoginOutcome.AuthenticationFailed or MikrotikLoginOutcome.PasswordExpired);
        var message = reachable > 0
            ? $"None of the {candidates.Count} router(s) accepted the given credentials ({reachable} rejected login, details in Attempts)."
            : $"Found {candidates.Count} router(s) but none was reachable over the API (port {options.Port ?? (options.UseTls ? 8729 : 8728)}). Details in Attempts.";
        throw new MikrotikDeviceNotFoundException(message, list);
    }

    private async Task<(MikrotikClient Client, MikrotikCredentials Credentials)?> TryDeviceAsync(
        MikrotikNeighbor neighbor, MikrotikLoginScanOptions options, ConcurrentQueue<MikrotikLoginAttempt> attempts, CancellationToken cancellationToken)
    {
        var addresses = neighbor.GetConnectionCandidates();
        if (addresses.Count == 0)
        {
            attempts.Enqueue(new MikrotikLoginAttempt(neighbor, null, null, MikrotikLoginOutcome.Unreachable, "No usable address (no IPv4 announced and no IPv6 link-local scope)."));
            return null;
        }

        foreach (var address in addresses)
        {
            var host = address.ToString(); // keeps the IPv6 scope id (fe80::...%12)
            var addressAnswered = false;
            foreach (var credentials in options.Credentials)
            {
                if (cancellationToken.IsCancellationRequested)
                    return null;
                var connection = new MikrotikConnectionOptions
                {
                    Host = host,
                    Port = options.Port,
                    UseTls = options.UseTls,
                    Username = credentials.Username,
                    Password = credentials.Password,
                    ConnectTimeout = options.ConnectTimeout,
                    CommandTimeout = options.CommandTimeout,
                };
                try
                {
                    var client = await MikrotikClient.ConnectAsync(connection, _loggerFactory.CreateLogger<MikrotikClient>(), cancellationToken).ConfigureAwait(false);
                    attempts.Enqueue(new MikrotikLoginAttempt(neighbor, host, credentials.Username, MikrotikLoginOutcome.Success, null));
                    return (client, credentials);
                }
                catch (MikrotikPasswordExpiredException e)
                {
                    addressAnswered = true;
                    attempts.Enqueue(new MikrotikLoginAttempt(neighbor, host, credentials.Username, MikrotikLoginOutcome.PasswordExpired, e.RouterMessage));
                }
                catch (MikrotikAuthenticationException e)
                {
                    addressAnswered = true;
                    attempts.Enqueue(new MikrotikLoginAttempt(neighbor, host, credentials.Username, MikrotikLoginOutcome.AuthenticationFailed, e.RouterMessage ?? e.Message));
                }
                catch (MikrotikConnectionException e)
                {
                    attempts.Enqueue(new MikrotikLoginAttempt(neighbor, host, credentials.Username, MikrotikLoginOutcome.Unreachable, e.Message));
                    break;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return null;
                }
                catch (Exception e) when (e is MikrotikException or IOException)
                {
                    attempts.Enqueue(new MikrotikLoginAttempt(neighbor, host, credentials.Username, MikrotikLoginOutcome.Error, e.Message));
                }
            }

            // The router answered on this address; other addresses lead to the same router and the same result.
            if (addressAnswered)
                return null;
        }
        return null;
    }
}
