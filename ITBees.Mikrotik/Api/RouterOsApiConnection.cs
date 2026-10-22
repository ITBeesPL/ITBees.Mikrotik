using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ITBees.Mikrotik.Api;

/// <summary>A logged-in RouterOS API session. Commands are executed one at a time.</summary>
public interface IRouterOsApiConnection : IAsyncDisposable, IDisposable
{
    /// <summary>Router address as used for the connection.</summary>
    string Host { get; }

    /// <summary>False after the router closed the session or a command timed out.</summary>
    bool IsConnected { get; }

    IPEndPoint? LocalEndPoint { get; }

    IPEndPoint? RemoteEndPoint { get; }

    /// <summary>Runs a command and returns its data items.</summary>
    /// <exception cref="MikrotikCommandException">The router answered with !trap.</exception>
    /// <exception cref="MikrotikConnectionException">The connection broke or the command timed out.</exception>
    Task<RouterOsResponse> ExecuteAsync(RouterOsCommand command, CancellationToken cancellationToken = default);
}

/// <summary>RouterOS API client over TCP (8728) or TLS (8729), IPv4 or IPv6 (including link-local with scope).</summary>
public sealed class RouterOsApiConnection : IRouterOsApiConnection
{
    private readonly TcpClient _tcpClient;
    private readonly Stream _stream;
    private readonly TimeSpan _commandTimeout;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private long _tagCounter;
    private volatile bool _broken;
    private bool _disposed;

    private RouterOsApiConnection(string host, TcpClient tcpClient, Stream stream, TimeSpan commandTimeout, ILogger logger)
    {
        Host = host;
        _tcpClient = tcpClient;
        _stream = stream;
        _commandTimeout = commandTimeout;
        _logger = logger;
        LocalEndPoint = tcpClient.Client.LocalEndPoint as IPEndPoint;
        RemoteEndPoint = tcpClient.Client.RemoteEndPoint as IPEndPoint;
    }

    public string Host { get; }

    public bool IsConnected => !_disposed && !_broken && _tcpClient.Connected;

    public IPEndPoint? LocalEndPoint { get; }

    public IPEndPoint? RemoteEndPoint { get; }

    /// <summary>Connects and logs in (RouterOS 6.43+ plain login, with fallback to the legacy MD5 challenge).</summary>
    /// <exception cref="MikrotikAuthenticationException">Wrong user name or password.</exception>
    /// <exception cref="MikrotikConnectionException">The API port is unreachable.</exception>
    public static async Task<RouterOsApiConnection> ConnectAsync(MikrotikConnectionOptions options, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.Host))
            throw new ArgumentException("Host is required.", nameof(options));
        logger ??= NullLogger.Instance;

        var host = options.Host.Trim();
        var tcpClient = await OpenTcpAsync(host, options.EffectivePort, options.ConnectTimeout, cancellationToken).ConfigureAwait(false);
        Stream stream = tcpClient.GetStream();
        try
        {
            if (options.UseTls)
            {
                var ssl = new SslStream(stream, false, (_, _, _, errors) => options.AcceptAnyCertificate || errors == SslPolicyErrors.None);
                using var tlsTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                tlsTimeout.CancelAfter(options.ConnectTimeout);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, tlsTimeout.Token).ConfigureAwait(false);
                stream = ssl;
            }
        }
        catch (Exception e) when (e is IOException or AuthenticationException || (e is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            tcpClient.Dispose();
            throw new MikrotikConnectionException(host, $"TLS handshake with {host}:{options.EffectivePort} failed: {e.Message}", e);
        }

        var connection = new RouterOsApiConnection(host, tcpClient, stream, options.CommandTimeout, logger);
        try
        {
            await connection.LoginAsync(options.Username, options.Password, cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<RouterOsResponse> ExecuteAsync(RouterOsCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_broken)
            throw new MikrotikConnectionException(Host, $"The API session with {Host} is closed; reconnect to continue.");

        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        var stopwatch = Stopwatch.StartNew();
        string? trapMessage = null;
        int? trapCategory = null;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_commandTimeout);
            var tag = Interlocked.Increment(ref _tagCounter).ToString(CultureInfo.InvariantCulture);
            await RouterOsWordCodec.WriteSentenceAsync(_stream, command.ToWords(tag), timeout.Token).ConfigureAwait(false);

            var records = new List<RouterOsRecord>();
            while (true)
            {
                var words = await RouterOsWordCodec.ReadSentenceAsync(_stream, timeout.Token).ConfigureAwait(false);
                if (words.Count == 0)
                    continue;
                var reply = RouterOsReply.Parse(words);
                if (reply.Type == RouterOsReplyType.Fatal)
                {
                    _broken = true;
                    if (trapMessage != null)
                        throw new MikrotikCommandException(Host, command.ToCliString(), trapMessage, trapCategory);
                    throw new MikrotikConnectionException(Host, $"{Host} closed the API session: {reply.Message ?? "no reason given"}.");
                }
                if (reply.Tag != null && reply.Tag != tag)
                    continue;

                switch (reply.Type)
                {
                    case RouterOsReplyType.Data:
                        records.Add(new RouterOsRecord(new Dictionary<string, string>(reply.Attributes)));
                        break;
                    case RouterOsReplyType.Trap:
                        trapMessage ??= reply.Message ?? "unknown error";
                        trapCategory ??= reply.Attributes.TryGetValue("category", out var category) && int.TryParse(category, out var c) ? c : null;
                        break;
                    case RouterOsReplyType.Done:
                        _logger.LogDebug("{Host} {Command} -> {Result} in {Elapsed} ms", Host, command.ToCliString(), trapMessage ?? $"{records.Count} item(s)", stopwatch.ElapsedMilliseconds);
                        if (trapMessage != null)
                            throw new MikrotikCommandException(Host, command.ToCliString(), trapMessage, trapCategory);
                        return new RouterOsResponse(records, reply.Attributes);
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _broken = true;
            throw new MikrotikConnectionException(Host, $"No reply from {Host} to '{command.ToCliString()}' within {_commandTimeout.TotalSeconds:0.#} s.", isTimeout: true);
        }
        catch (OperationCanceledException)
        {
            // The reply may still arrive later and would be read as the reply to the next command.
            _broken = true;
            throw;
        }
        catch (Exception e) when (e is IOException or SocketException or EndOfStreamException or ObjectDisposedException)
        {
            _broken = true;
            if (trapMessage != null)
                throw new MikrotikCommandException(Host, command.ToCliString(), trapMessage, trapCategory);
            throw new MikrotikConnectionException(Host, $"Connection to {Host} lost during '{command.ToCliString()}': {e.Message}", e);
        }
        catch (FormatException e)
        {
            _broken = true;
            throw new MikrotikProtocolException(Host, $"Invalid API data from {Host}: {e.Message}", e);
        }
        finally
        {
            _lock.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _stream.Dispose();
        _tcpClient.Dispose();
        _lock.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    internal static string LegacyLoginResponse(string password, string challengeHex)
    {
        var challenge = Convert.FromHexString(challengeHex);
        var passwordBytes = RouterOsWordCodec.Encoding.GetBytes(password);
        var data = new byte[1 + passwordBytes.Length + challenge.Length];
        passwordBytes.CopyTo(data, 1);
        challenge.CopyTo(data, 1 + passwordBytes.Length);
        return "00" + Convert.ToHexString(MD5.HashData(data)).ToLowerInvariant();
    }

    private async Task LoginAsync(string username, string password, CancellationToken cancellationToken)
    {
        try
        {
            var response = await ExecuteAsync(new RouterOsCommand("/login").With("name", username).With("password", password), cancellationToken).ConfigureAwait(false);
            var challenge = response.Ret;
            if (challenge is { Length: 32 } && challenge.All(Uri.IsHexDigit))
            {
                // RouterOS older than 6.43 ignores =password= and returns an MD5 challenge.
                await ExecuteAsync(
                        new RouterOsCommand("/login").With("name", username).With("response", LegacyLoginResponse(password, challenge)),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            _logger.LogDebug("Logged in to {Host} as {User}", Host, username);
        }
        catch (MikrotikCommandException e)
        {
            var message = e.RouterMessage;
            if (message.Contains("expired", StringComparison.OrdinalIgnoreCase) || message.Contains("change password", StringComparison.OrdinalIgnoreCase))
                throw new MikrotikPasswordExpiredException(Host, $"{Host}: the password of '{username}' has expired and must be changed (e.g. in Winbox/WebFig) before API login. Router said: {message}", message);
            throw new MikrotikAuthenticationException(Host, $"{Host} rejected login '{username}': {message}", message);
        }
    }

    private static async Task<TcpClient> OpenTcpAsync(string host, int port, TimeSpan connectTimeout, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(connectTimeout);
        TcpClient? tcpClient = null;
        try
        {
            if (IPAddress.TryParse(host, out var address))
            {
                tcpClient = new TcpClient(address.AddressFamily) { NoDelay = true };
                await tcpClient.ConnectAsync(new IPEndPoint(address, port), timeout.Token).ConfigureAwait(false);
            }
            else
            {
                tcpClient = new TcpClient(AddressFamily.InterNetworkV6) { NoDelay = true };
                tcpClient.Client.DualMode = true;
                await tcpClient.ConnectAsync(host, port, timeout.Token).ConfigureAwait(false);
            }
            return tcpClient;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            tcpClient?.Dispose();
            throw new MikrotikConnectionException(host, $"Timed out connecting to {host}:{port} after {connectTimeout.TotalSeconds:0.#} s.", isTimeout: true);
        }
        catch (SocketException e)
        {
            tcpClient?.Dispose();
            var hint = e.SocketErrorCode == SocketError.ConnectionRefused ? " (API service disabled or port blocked)" : string.Empty;
            throw new MikrotikConnectionException(host, $"Cannot connect to {host}:{port}: {e.Message}{hint}", e);
        }
        catch
        {
            tcpClient?.Dispose();
            throw;
        }
    }
}
