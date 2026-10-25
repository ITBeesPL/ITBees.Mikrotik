using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ITBees.Mikrotik.Lte;

public sealed class HiLinkModemOptions
{
    /// <summary>Timeout of one HTTP request to the stick.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>How long <see cref="HiLinkModem.EnsureApnAsync"/> waits for the data connection after switching the profile.</summary>
    public TimeSpan ConnectWait { get; set; } = TimeSpan.FromSeconds(40);

    /// <summary>Name of the dial-up profile the library creates in the stick.</summary>
    public string ProfileName { get; set; } = "itbees";

    /// <summary>Pause between switching mobile data off and on again (forces a redial with the new profile).</summary>
    public TimeSpan RedialPause { get; set; } = TimeSpan.FromSeconds(2);
}

/// <summary>What a HiLink stick reports about itself. Fields the firmware does not return are null.</summary>
public sealed record HiLinkModemStatus(
    string? DeviceName,
    int? ConnectionStatus,
    string ConnectionText,
    string? Operator,
    string? NetworkType,
    int? SignalBars,
    int? Rssi,
    int? Rsrp,
    int? Rsrq,
    int? Sinr,
    bool? SimReady,
    bool? MobileData,
    string? ProfileName,
    string? Apn)
{
    /// <summary>The stick has a mobile data connection (status 901).</summary>
    public bool Connected => ConnectionStatus == HiLinkModem.StatusConnected;
}

/// <summary>Result of <see cref="HiLinkModem.EnsureApnAsync"/>.</summary>
public sealed record HiLinkApnResult(bool Changed, string Apn, string? PreviousApn, string? ProfileName, HiLinkModemStatus Status)
{
    public override string ToString() =>
        (Changed ? $"APN {PreviousApn ?? "-"} -> {Apn} (profile {ProfileName})" : $"APN {Apn} already set (profile {ProfileName})")
        + $", {Status.ConnectionText}";
}

/// <summary>The stick refused a request (error code from its API) or answered something unexpected.</summary>
public sealed class HiLinkException : Exception
{
    public HiLinkException(string message, int? errorCode = null, Exception? inner = null)
        : base(message, inner)
    {
        ErrorCode = errorCode;
    }

    /// <summary>Code from &lt;error&gt;&lt;code&gt; (e.g. 100003 = login required), null for other failures.</summary>
    public int? ErrorCode { get; }
}

/// <summary>A HiLink LTE stick's web API (see <see cref="HiLinkModem"/>).</summary>
public interface IHiLinkModem : IDisposable
{
    string Address { get; }

    Task<HiLinkModemStatus> ReadStatusAsync(CancellationToken cancellationToken = default);

    Task<HiLinkApnResult> EnsureApnAsync(string apn, CancellationToken cancellationToken = default);
}

/// <summary>
/// Huawei HiLink LTE stick (E3372h and similar) over its web API at http://192.168.8.1. RouterOS only sees the stick as
/// an Ethernet interface with its own DHCP: the APN lives in the stick, so it is set here, from a computer whose
/// traffic reaches the stick (the column behind the router: the router masquerades it out of lte1).
/// Works without a login on sticks whose web panel has none (the default of HiLink firmware 22.x).
/// </summary>
public sealed class HiLinkModem : IHiLinkModem
{
    public const int StatusConnecting = 900;
    public const int StatusConnected = 901;
    public const int StatusDisconnected = 902;
    public const string DefaultAddress = "192.168.8.1";

    private static readonly Regex ApnPattern = new("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", RegexOptions.CultureInvariant);
    private static readonly int[] TokenErrors = { 125001, 125002, 125003 };

    private readonly HttpClient _http;
    private readonly HiLinkModemOptions _options;
    private readonly ILogger _logger;

    public HiLinkModem(string address, HiLinkModemOptions? options = null, HttpMessageHandler? handler = null, ILogger? logger = null)
    {
        _options = options ?? new HiLinkModemOptions();
        _logger = logger ?? NullLogger.Instance;
        var host = IPAddress.TryParse(address, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{address}]" : address;
        _http = new HttpClient(handler ?? new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
        {
            BaseAddress = new Uri($"http://{host}/"),
            Timeout = _options.RequestTimeout,
        };
        Address = address;
    }

    public string Address { get; }

    /// <summary>True when <paramref name="apn"/> can be sent to the stick (letters, digits, dot, dash, underscore).</summary>
    public static bool IsValidApn(string? apn) => apn != null && ApnPattern.IsMatch(apn);

    /// <summary>Connection state, operator, network, signal, SIM and the APN of the default profile.</summary>
    public async Task<HiLinkModemStatus> ReadStatusAsync(CancellationToken cancellationToken = default)
    {
        // The status page is the one every HiLink firmware has: if it fails, this is not a reachable HiLink stick.
        var status = await GetAsync("api/monitoring/status", cancellationToken).ConfigureAwait(false);
        var device = await TryGetAsync("api/device/basic_information", cancellationToken).ConfigureAwait(false);
        var plmn = await TryGetAsync("api/net/current-plmn", cancellationToken).ConfigureAwait(false);
        var signal = await TryGetAsync("api/device/signal", cancellationToken).ConfigureAwait(false);
        var pin = await TryGetAsync("api/pin/status", cancellationToken).ConfigureAwait(false);
        var dataSwitch = await TryGetAsync("api/dialup/mobile-dataswitch", cancellationToken).ConfigureAwait(false);
        var profiles = await TryReadProfilesAsync(cancellationToken).ConfigureAwait(false);

        var code = Int(status, "ConnectionStatus");
        var current = profiles?.Current;
        return new HiLinkModemStatus(
            Text(device, "devicename") ?? Text(device, "DeviceName"),
            code,
            DescribeConnectionStatus(code),
            Text(plmn, "FullName") ?? Text(plmn, "ShortName"),
            DescribeNetworkType(Int(status, "CurrentNetworkTypeEx"), Int(status, "CurrentNetworkType")),
            Int(status, "SignalIcon"),
            Int(signal, "rssi"),
            Int(signal, "rsrp"),
            Int(signal, "rsrq"),
            Int(signal, "sinr"),
            Text(pin, "SimState") is { } simState ? simState == "257" : Int(status, "SimStatus") is { } sim ? sim == 1 : null,
            Int(dataSwitch, "dataswitch") is { } on ? on == 1 : null,
            current?.Name,
            current?.Apn);
    }

    /// <summary>
    /// Makes <paramref name="apn"/> the APN of the stick's default profile: picks a profile that already has it, or
    /// updates / creates the library's own profile (<see cref="HiLinkModemOptions.ProfileName"/>), then switches
    /// mobile data off and on so the stick dials with it and waits for the connection.
    /// </summary>
    /// <exception cref="HiLinkException">The stick refused a change or kept its old profile.</exception>
    public async Task<HiLinkApnResult> EnsureApnAsync(string apn, CancellationToken cancellationToken = default)
    {
        if (!IsValidApn(apn))
            throw new ArgumentException($"'{apn}' is not a valid APN.", nameof(apn));

        var profiles = await ReadProfilesAsync(cancellationToken).ConfigureAwait(false);
        var previous = profiles.Current;
        if (previous != null && SameApn(previous.Apn, apn))
        {
            var unchanged = await ReadStatusAsync(cancellationToken).ConfigureAwait(false);
            return new HiLinkApnResult(false, apn, previous.Apn, previous.Name, unchanged);
        }

        var target = profiles.Items.FirstOrDefault(p => SameApn(p.Apn, apn) && p.Name == _options.ProfileName)
                     ?? profiles.Items.FirstOrDefault(p => SameApn(p.Apn, apn));
        if (target == null)
        {
            var own = profiles.Items.FirstOrDefault(p => p.Name == _options.ProfileName && !p.ReadOnly);
            if (own != null)
            {
                _logger.LogInformation("HiLink {Address}: profile {Name} APN {Old} -> {Apn}", Address, own.Name, own.Apn, apn);
                await PostAsync("api/dialup/profiles", ProfileRequest(modify: 2, own.Index, setDefault: own.Index, apn), cancellationToken).ConfigureAwait(false);
            }
            else
            {
                _logger.LogInformation("HiLink {Address}: adding profile {Name} with APN {Apn}", Address, _options.ProfileName, apn);
                await PostAsync("api/dialup/profiles", ProfileRequest(modify: 1, index: null, setDefault: profiles.CurrentIndex ?? 0, apn), cancellationToken).ConfigureAwait(false);
            }
            profiles = await ReadProfilesAsync(cancellationToken).ConfigureAwait(false);
            target = profiles.Items.FirstOrDefault(p => p.Name == _options.ProfileName && SameApn(p.Apn, apn))
                     ?? throw new HiLinkException($"The stick did not save the profile {_options.ProfileName} with APN {apn}.");
        }

        if (profiles.CurrentIndex != target.Index)
        {
            _logger.LogInformation("HiLink {Address}: default profile {Old} -> {New}", Address, profiles.Current?.Name, target.Name);
            await PostAsync("api/dialup/profiles", new XElement("request",
                new XElement("Delete", 0),
                new XElement("SetDefault", target.Index),
                new XElement("Modify", 0)), cancellationToken).ConfigureAwait(false);
            profiles = await ReadProfilesAsync(cancellationToken).ConfigureAwait(false);
            if (profiles.CurrentIndex != target.Index)
                throw new HiLinkException($"The stick kept profile {profiles.Current?.Name ?? "?"} as the default instead of {target.Name}.");
        }

        await RedialAsync(cancellationToken).ConfigureAwait(false);
        var status = await WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        return new HiLinkApnResult(true, apn, previous?.Apn, target.Name, status);
    }

    /// <summary>Human-readable meaning of the stick's ConnectionStatus code (codes of the HiLink web panel).</summary>
    public static string DescribeConnectionStatus(int? code) => code switch
    {
        null => "unknown",
        StatusConnecting => "connecting",
        StatusConnected => "connected",
        StatusDisconnected => "disconnected",
        903 => "disconnecting",
        904 => "connection failed or mobile data disabled",
        2 or 3 or 5 or 8 or 20 or 21 or 23 or 27 or 28 or 29 or 30 or 31 or 32 or 33 => $"connection failed: the profile (APN) is not accepted ({code})",
        7 or 11 or 14 or 37 or (>= 131079 and <= 131089) => $"network access not allowed ({code})",
        12 or 13 => $"roaming not allowed ({code})",
        201 => "data limit reached (201)",
        112 or 113 => $"automatic connection off ({code})",
        114 or 115 => $"reconnect off ({code})",
        _ => $"status {code}",
    };

    private static string? DescribeNetworkType(int? extended, int? basic) => extended switch
    {
        101 => "LTE",
        111 => "5G",
        >= 41 and <= 46 => "3G",
        >= 1 and <= 3 => "2G",
        _ => basic switch
        {
            19 => "LTE",
            >= 4 and <= 9 => "3G",
            >= 1 and <= 3 => "2G",
            _ => null,
        },
    };

    private static bool SameApn(string? a, string? b) => string.Equals(a?.Trim(), b?.Trim(), StringComparison.OrdinalIgnoreCase);

    private XElement ProfileRequest(int modify, int? index, int setDefault, string apn) => new("request",
        new XElement("Delete", 0),
        new XElement("SetDefault", setDefault),
        new XElement("Modify", modify),
        new XElement("Profile",
            new XElement("Index", index?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
            new XElement("IsValid", 1),
            new XElement("Name", _options.ProfileName),
            new XElement("ApnIsStatic", 1),
            new XElement("ApnName", apn),
            new XElement("DialupNum", "*99#"),
            new XElement("Username", string.Empty),
            new XElement("Password", string.Empty),
            new XElement("AuthMode", 0),
            new XElement("IpIsStatic", string.Empty),
            new XElement("IpAddress", string.Empty),
            new XElement("DnsIsStatic", string.Empty),
            new XElement("PrimaryDns", string.Empty),
            new XElement("SecondaryDns", string.Empty),
            new XElement("ReadOnly", 0),
            new XElement("iptype", 0)));

    /// <summary>Mobile data off and on: the stick dials again with the default profile.</summary>
    private async Task RedialAsync(CancellationToken cancellationToken)
    {
        try
        {
            await PostAsync("api/dialup/mobile-dataswitch", new XElement("request", new XElement("dataswitch", 0)), cancellationToken).ConfigureAwait(false);
            await Task.Delay(_options.RedialPause, cancellationToken).ConfigureAwait(false);
            await PostAsync("api/dialup/mobile-dataswitch", new XElement("request", new XElement("dataswitch", 1)), cancellationToken).ConfigureAwait(false);
        }
        catch (HiLinkException e)
        {
            // Older firmware has no data switch; it redials on its own after the profile change.
            _logger.LogInformation("HiLink {Address}: no data switch ({Message}); waiting for the stick to redial.", Address, e.Message);
        }
    }

    private async Task<HiLinkModemStatus> WaitForConnectionAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + _options.ConnectWait;
        while (true)
        {
            var status = await ReadStatusAsync(cancellationToken).ConfigureAwait(false);
            if (status.Connected || DateTime.UtcNow >= deadline)
                return status;
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
        }
    }

    // ---------------------------------------------------------------- profiles

    private sealed record Profile(int Index, string? Name, string? Apn, bool ReadOnly);

    private sealed record Profiles(int? CurrentIndex, IReadOnlyList<Profile> Items)
    {
        public Profile? Current => Items.FirstOrDefault(p => p.Index == CurrentIndex);
    }

    private async Task<Profiles?> TryReadProfilesAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await ReadProfilesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (HiLinkException)
        {
            return null;
        }
    }

    private async Task<Profiles> ReadProfilesAsync(CancellationToken cancellationToken)
    {
        var response = await GetAsync("api/dialup/profiles", cancellationToken).ConfigureAwait(false);
        var items = response.Descendants("Profile")
            .Select(p => (Index: Int(p, "Index"), p))
            .Where(x => x.Index != null)
            .Select(x => new Profile(x.Index!.Value, Text(x.p, "Name"), Text(x.p, "ApnName"), Text(x.p, "ReadOnly") == "1"))
            .ToList();
        return new Profiles(Int(response, "CurrentProfile"), items);
    }

    // ---------------------------------------------------------------- HTTP

    private async Task<XElement?> TryGetAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await GetAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (HiLinkException e)
        {
            _logger.LogDebug("HiLink {Address}: {Path} unavailable: {Message}", Address, path, e.Message);
            return null;
        }
    }

    private Task<XElement> GetAsync(string path, CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Get, path, null, cancellationToken);

    private async Task PostAsync(string path, XElement request, CancellationToken cancellationToken)
    {
        var response = await SendAsync(HttpMethod.Post, path, request, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(response.Value.Trim(), "OK", StringComparison.OrdinalIgnoreCase))
            throw new HiLinkException($"The stick answered {path} with '{response}' instead of OK.");
    }

    /// <summary>One request with a fresh session and token (POST tokens are single-use); retried once on a token error.</summary>
    private async Task<XElement> SendAsync(HttpMethod method, string path, XElement? body, CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            var (cookie, token) = await GetSessionAsync(cancellationToken).ConfigureAwait(false);
            using var request = new HttpRequestMessage(method, path);
            if (cookie != null)
                request.Headers.TryAddWithoutValidation("Cookie", cookie);
            if (token != null)
                request.Headers.TryAddWithoutValidation("__RequestVerificationToken", token);
            if (body != null)
                request.Content = new StringContent("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + body.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "application/x-www-form-urlencoded");

            var xml = await ReadXmlAsync(request, path, cancellationToken).ConfigureAwait(false);
            if (xml.Name.LocalName == "error")
            {
                var code = Int(xml, "code");
                if (code != null && TokenErrors.Contains(code.Value) && attempt == 1)
                    continue;
                throw new HiLinkException(
                    code == 100003 ? $"The stick wants a login for {path} (error 100003): switch the login off in its web panel." : $"The stick refused {path} (error {code?.ToString(CultureInfo.InvariantCulture) ?? "?"}).",
                    code);
            }
            return xml;
        }
    }

    private async Task<(string? Cookie, string? Token)> GetSessionAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "api/webserver/SesTokInfo");
        var xml = await ReadXmlAsync(request, "api/webserver/SesTokInfo", cancellationToken).ConfigureAwait(false);
        if (xml.Name.LocalName == "response")
            return (Text(xml, "SesInfo"), Text(xml, "TokInfo"));

        // Newer firmware: session cookie from the home page, token from api/webserver/token.
        using var home = new HttpRequestMessage(HttpMethod.Get, "html/home.html");
        using var homeResponse = await SendRawAsync(home, "html/home.html", cancellationToken).ConfigureAwait(false);
        var cookie = homeResponse.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Select(v => v.Split(';')[0]).FirstOrDefault(v => v.StartsWith("SessionID", StringComparison.OrdinalIgnoreCase))
            : null;
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Get, "api/webserver/token");
        if (cookie != null)
            tokenRequest.Headers.TryAddWithoutValidation("Cookie", cookie);
        var tokenXml = await ReadXmlAsync(tokenRequest, "api/webserver/token", cancellationToken).ConfigureAwait(false);
        var token = Text(tokenXml, "token");
        return (cookie, token is { Length: > 32 } ? token[^32..] : token);
    }

    private async Task<XElement> ReadXmlAsync(HttpRequestMessage request, string path, CancellationToken cancellationToken)
    {
        using var response = await SendRawAsync(request, path, cancellationToken).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return XElement.Parse(text.Trim());
        }
        catch (System.Xml.XmlException e)
        {
            throw new HiLinkException($"The stick answered {path} with HTTP {(int)response.StatusCode} and no XML.", inner: e);
        }
    }

    private async Task<HttpResponseMessage> SendRawAsync(HttpRequestMessage request, string path, CancellationToken cancellationToken)
    {
        try
        {
            return await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            throw new HiLinkUnreachableException($"No answer from the stick at {Address} ({path}): {e.Message}", e);
        }
        catch (TaskCanceledException e) when (!cancellationToken.IsCancellationRequested)
        {
            throw new HiLinkUnreachableException($"No answer from the stick at {Address} within {_options.RequestTimeout.TotalSeconds:0} s ({path}).", e);
        }
    }

    private static string? Text(XElement? parent, string name)
    {
        var value = parent?.Element(name)?.Value;
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <summary>Leading integer of a value such as "-104dBm" or "33".</summary>
    private static int? Int(XElement? parent, string name)
    {
        var value = Text(parent, name);
        if (value == null)
            return null;
        var match = Regex.Match(value, @"^[-+]?\d+");
        return match.Success && int.TryParse(match.Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number) ? number : null;
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>Nothing answered at the stick's address (not reachable from this computer, or no HiLink stick there).</summary>
public sealed class HiLinkUnreachableException : Exception
{
    public HiLinkUnreachableException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}
