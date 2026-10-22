using ITBees.Mikrotik.Api;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ITBees.Mikrotik;

/// <summary>Basic facts about a router, read right after login.</summary>
public sealed record MikrotikDeviceInfo
{
    public string? Identity { get; init; }

    /// <summary>Marketing name from /system/resource, e.g. "hEX PoE".</summary>
    public string? BoardName { get; init; }

    /// <summary>Hardware model from /system/routerboard, e.g. "RB960PGS". Null on CHR/x86.</summary>
    public string? Model { get; init; }

    public string? SerialNumber { get; init; }

    public string? Architecture { get; init; }

    public string? FirmwareVersion { get; init; }

    public required RouterOsVersion Version { get; init; }

    public TimeSpan? Uptime { get; init; }

    public override string ToString() =>
        $"{Identity ?? "?"} {Model ?? BoardName ?? "?"} S/N {SerialNumber ?? "?"} RouterOS {Version}";
}

/// <summary>A logged-in session with one router.</summary>
public interface IMikrotikClient : IAsyncDisposable, IDisposable
{
    /// <summary>Address used for the connection (IPv4, IPv6 link-local with scope, or DNS name).</summary>
    string Host { get; }

    string Username { get; }

    bool IsConnected { get; }

    MikrotikDeviceInfo Device { get; }

    /// <summary>Raw RouterOS API access for anything the library does not cover.</summary>
    IRouterOsApiConnection Api { get; }

    Task<MikrotikDeviceInfo> RefreshDeviceInfoAsync(CancellationToken cancellationToken = default);

    /// <summary>Prints a menu, e.g. <c>PrintAsync("/ip/address", ("interface", "bridge"))</c>.</summary>
    Task<IReadOnlyList<RouterOsRecord>> PrintAsync(string menu, params (string Name, string Value)[] where);

    /// <summary>Runs any command, e.g. <c>/system/reboot</c>.</summary>
    Task<RouterOsResponse> ExecuteAsync(RouterOsCommand command, CancellationToken cancellationToken = default);
}

public sealed class MikrotikClient : IMikrotikClient
{
    private readonly ILogger _logger;

    private MikrotikClient(IRouterOsApiConnection api, MikrotikConnectionOptions options, MikrotikDeviceInfo device, ILogger logger)
    {
        Api = api;
        Options = options;
        Device = device;
        _logger = logger;
    }

    public string Host => Api.Host;

    public string Username => Options.Username;

    public bool IsConnected => Api.IsConnected;

    public MikrotikDeviceInfo Device { get; private set; }

    public IRouterOsApiConnection Api { get; }

    /// <summary>Options used to connect (kept for reconnects and password verification).</summary>
    internal MikrotikConnectionOptions Options { get; }

    /// <summary>Connects, logs in and reads <see cref="Device"/>.</summary>
    /// <exception cref="MikrotikAuthenticationException">Wrong user name or password.</exception>
    /// <exception cref="MikrotikConnectionException">The router is unreachable.</exception>
    public static async Task<MikrotikClient> ConnectAsync(MikrotikConnectionOptions options, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        logger ??= NullLogger.Instance;
        var api = await RouterOsApiConnection.ConnectAsync(options, logger, cancellationToken).ConfigureAwait(false);
        try
        {
            var device = await ReadDeviceInfoAsync(api, cancellationToken).ConfigureAwait(false);
            logger.LogInformation("Connected to {Host}: {Device}", api.Host, device);
            return new MikrotikClient(api, options.Clone(), device, logger);
        }
        catch
        {
            await api.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Wraps an existing API session (used by tests and advanced callers).</summary>
    public static async Task<MikrotikClient> CreateAsync(IRouterOsApiConnection api, MikrotikConnectionOptions options, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        var device = await ReadDeviceInfoAsync(api, cancellationToken).ConfigureAwait(false);
        return new MikrotikClient(api, options.Clone(), device, logger ?? NullLogger.Instance);
    }

    public async Task<MikrotikDeviceInfo> RefreshDeviceInfoAsync(CancellationToken cancellationToken = default)
    {
        Device = await ReadDeviceInfoAsync(Api, cancellationToken).ConfigureAwait(false);
        return Device;
    }

    public async Task<IReadOnlyList<RouterOsRecord>> PrintAsync(string menu, params (string Name, string Value)[] where)
    {
        var command = new RouterOsCommand(menu.TrimEnd('/') + "/print");
        foreach (var (name, value) in where)
            command.Where(name, value);
        var response = await Api.ExecuteAsync(command).ConfigureAwait(false);
        return response.Records;
    }

    public Task<RouterOsResponse> ExecuteAsync(RouterOsCommand command, CancellationToken cancellationToken = default) =>
        Api.ExecuteAsync(command, cancellationToken);

    /// <summary>True when the given password logs in on a new, separate session (the current session is untouched).</summary>
    internal async Task<bool> VerifyPasswordAsync(string password, CancellationToken cancellationToken)
    {
        var options = Options.Clone();
        options.Password = password;
        try
        {
            await using var probe = await RouterOsApiConnection.ConnectAsync(options, _logger, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (MikrotikAuthenticationException)
        {
            return false;
        }
    }

    internal void UpdatePassword(string password) => Options.Password = password;

    public void Dispose() => Api.Dispose();

    public ValueTask DisposeAsync() => Api.DisposeAsync();

    private static async Task<MikrotikDeviceInfo> ReadDeviceInfoAsync(IRouterOsApiConnection api, CancellationToken cancellationToken)
    {
        var resource = (await api.ExecuteAsync(new RouterOsCommand("/system/resource/print"), cancellationToken).ConfigureAwait(false)).Records.FirstOrDefault();
        var identity = (await api.ExecuteAsync(new RouterOsCommand("/system/identity/print"), cancellationToken).ConfigureAwait(false)).Records.FirstOrDefault();
        RouterOsRecord? routerboard = null;
        try
        {
            routerboard = (await api.ExecuteAsync(new RouterOsCommand("/system/routerboard/print"), cancellationToken).ConfigureAwait(false)).Records.FirstOrDefault();
        }
        catch (MikrotikCommandException)
        {
            // CHR / x86 have no RouterBOARD menu.
        }

        RouterOsVersion.TryParse(resource?.Get("version"), out var version);
        return new MikrotikDeviceInfo
        {
            Identity = identity?.Get("name"),
            BoardName = resource?.Get("board-name"),
            Model = routerboard?.Get("model"),
            SerialNumber = routerboard?.Get("serial-number"),
            FirmwareVersion = routerboard?.Get("current-firmware"),
            Architecture = resource?.Get("architecture-name"),
            Version = version,
            Uptime = resource?.GetDuration("uptime"),
        };
    }
}
