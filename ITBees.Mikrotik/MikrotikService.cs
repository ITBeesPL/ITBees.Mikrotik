using ITBees.Mikrotik.Configuration;
using ITBees.Mikrotik.Discovery;
using ITBees.Mikrotik.Provisioning;
using ITBees.Mikrotik.Status;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ITBees.Mikrotik;

/// <summary>Everything needed to take a factory-new router to a configured parking router in one call.</summary>
public sealed class MikrotikSetupRequest
{
    /// <summary>Credentials to try on the discovered routers, e.g. admin + sticker password (and the standard parking password, so re-runs work).</summary>
    public IList<MikrotikCredentials> Credentials { get; set; } = new List<MikrotikCredentials>();

    public MikrotikConfigurationPackage Package { get; set; } = new();

    /// <summary>Optional: only routers matching this (e.g. a MAC from the label).</summary>
    public Func<MikrotikNeighbor, bool>? Filter { get; set; }

    public MndpDiscoveryOptions? Discovery { get; set; }

    public MikrotikProvisioningOptions? Provisioning { get; set; }
}

public sealed class MikrotikSetupResult
{
    public MikrotikSetupResult(MikrotikNeighbor device, string username, MikrotikProvisioningResult provisioning, IReadOnlyList<MikrotikLoginAttempt> attempts)
    {
        Device = device;
        Username = username;
        Provisioning = provisioning;
        Attempts = attempts;
    }

    /// <summary>The router that accepted the credentials.</summary>
    public MikrotikNeighbor Device { get; }

    public string Username { get; }

    public MikrotikProvisioningResult Provisioning { get; }

    public IReadOnlyList<MikrotikLoginAttempt> Attempts { get; }
}

/// <summary>Entry point of the library (register with <c>services.AddMikrotik()</c>).</summary>
public interface IMikrotikService
{
    /// <summary>Lists MikroTik routers on the local network segments (MNDP, like Winbox), regardless of their IP addressing.</summary>
    Task<IReadOnlyList<MikrotikNeighbor>> DiscoverAsync(MndpDiscoveryOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Connects to a known address and logs in.</summary>
    Task<IMikrotikClient> ConnectAsync(MikrotikConnectionOptions options, CancellationToken cancellationToken = default);

    /// <summary>Discovers routers and tries the credentials on each until one accepts them.</summary>
    /// <exception cref="MikrotikDeviceNotFoundException">No router accepted the credentials (Attempts explain why).</exception>
    Task<MikrotikLoginScanResult> FindAndLoginAsync(MikrotikLoginScanOptions options, MndpDiscoveryOptions? discovery = null, CancellationToken cancellationToken = default);

    /// <summary>Applies a configuration package (idempotent). See <see cref="MikrotikProvisioner"/>.</summary>
    Task<MikrotikProvisioningResult> ApplyConfigurationAsync(IMikrotikClient client, MikrotikConfigurationPackage package, MikrotikProvisioningOptions? options = null, CancellationToken cancellationToken = default);

    Task<MikrotikStatus> GetStatusAsync(IMikrotikClient client, MikrotikConfigurationPackage? package = null, CancellationToken cancellationToken = default);

    /// <summary>Ethernet ports: link, speed, PoE and the devices learned on each. See <see cref="MikrotikPorts"/>.</summary>
    Task<IReadOnlyList<MikrotikPortStatus>> GetPortsAsync(IMikrotikClient client, CancellationToken cancellationToken = default);

    /// <summary>PoE output of the port off for a while and back on (restarts a PoE camera). Returns what was done.</summary>
    Task<string> PowerCyclePortAsync(IMikrotikClient client, string port, TimeSpan duration, CancellationToken cancellationToken = default);

    /// <summary>Discover, find the router that accepts the credentials, apply the package, close the session.</summary>
    Task<MikrotikSetupResult> SetupAsync(MikrotikSetupRequest request, CancellationToken cancellationToken = default);
}

public sealed class MikrotikService : IMikrotikService
{
    private readonly ILoggerFactory _loggerFactory;

    public MikrotikService(ILoggerFactory? loggerFactory = null)
    {
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
    }

    public Task<IReadOnlyList<MikrotikNeighbor>> DiscoverAsync(MndpDiscoveryOptions? options = null, CancellationToken cancellationToken = default) =>
        new MndpDiscovery(_loggerFactory.CreateLogger<MndpDiscovery>()).DiscoverAsync(options, cancellationToken);

    public async Task<IMikrotikClient> ConnectAsync(MikrotikConnectionOptions options, CancellationToken cancellationToken = default) =>
        await MikrotikClient.ConnectAsync(options, _loggerFactory.CreateLogger<MikrotikClient>(), cancellationToken).ConfigureAwait(false);

    public async Task<MikrotikLoginScanResult> FindAndLoginAsync(MikrotikLoginScanOptions options, MndpDiscoveryOptions? discovery = null, CancellationToken cancellationToken = default)
    {
        var neighbors = await DiscoverAsync(discovery, cancellationToken).ConfigureAwait(false);
        return await new MikrotikLoginScanner(_loggerFactory).FindAsync(neighbors, options, cancellationToken).ConfigureAwait(false);
    }

    public Task<MikrotikProvisioningResult> ApplyConfigurationAsync(IMikrotikClient client, MikrotikConfigurationPackage package, MikrotikProvisioningOptions? options = null, CancellationToken cancellationToken = default) =>
        new MikrotikProvisioner(_loggerFactory.CreateLogger<MikrotikProvisioner>()).ApplyAsync(client, package, options, cancellationToken);

    public Task<MikrotikStatus> GetStatusAsync(IMikrotikClient client, MikrotikConfigurationPackage? package = null, CancellationToken cancellationToken = default) =>
        new MikrotikStatusReader().ReadAsync(client, package, cancellationToken);

    public Task<IReadOnlyList<MikrotikPortStatus>> GetPortsAsync(IMikrotikClient client, CancellationToken cancellationToken = default) =>
        MikrotikPorts.ReadAsync(client, cancellationToken);

    public Task<string> PowerCyclePortAsync(IMikrotikClient client, string port, TimeSpan duration, CancellationToken cancellationToken = default) =>
        MikrotikPorts.PowerCycleAsync(client, port, duration, cancellationToken);

    public async Task<MikrotikSetupResult> SetupAsync(MikrotikSetupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        // Fail on an invalid package before touching the network.
        request.Package.Validate().ThrowIfInvalid();

        var credentials = request.Credentials.ToList();
        var newPassword = request.Package.Security.AdminPassword;
        if (!string.IsNullOrEmpty(newPassword))
        {
            // After a successful run the router only accepts the new password; trying it too makes the call repeatable.
            foreach (var user in credentials.Select(c => c.Username).Distinct().ToList())
                if (!credentials.Any(c => c.Username == user && c.Password == newPassword))
                    credentials.Add(new MikrotikCredentials(user, newPassword));
        }

        var scan = await FindAndLoginAsync(
                new MikrotikLoginScanOptions { Credentials = credentials, Filter = request.Filter },
                request.Discovery,
                cancellationToken)
            .ConfigureAwait(false);
        await using var client = scan.Client;
        var result = await ApplyConfigurationAsync(client, request.Package, request.Provisioning, cancellationToken).ConfigureAwait(false);
        return new MikrotikSetupResult(scan.Device, scan.Credentials.Username, result, scan.Attempts);
    }
}

public static class MikrotikServiceCollectionExtensions
{
    /// <summary>Registers <see cref="IMikrotikService"/> as a singleton.</summary>
    public static IServiceCollection AddMikrotik(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IMikrotikService, MikrotikService>();
        return services;
    }
}
