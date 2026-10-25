using System.Net;
using System.Text;
using System.Xml.Linq;
using ITBees.Mikrotik.Lte;

namespace ITBees.Mikrotik.Tests;

public class HiLinkModemTests
{
    /// <summary>
    /// A Huawei E3372 (HiLink 22.200, web UI 17.100) as it answered on 2026-10-25: a used stick with an "o2" profile
    /// (APN internetn) and a Play SIM - registered on LTE, but the data connection fails (status 33).
    /// </summary>
    private sealed class FakeStick : HttpMessageHandler
    {
        public List<(int Index, string Name, string Apn, bool ReadOnly)> Profiles { get; } = new()
        {
            (1, "Connect Mobile", "broadband", true),
            (2, "o2", "internetn", false),
        };

        public int CurrentProfile { get; set; } = 2;
        public int DataSwitch { get; set; } = 1;
        public string WorkingApn { get; set; } = "internet";
        public bool LoginRequired { get; set; }
        public int TokenErrorsToSend { get; set; }
        public List<string> Posts { get; } = new();
        private int _token;

        private int ConnectionStatus =>
            DataSwitch == 0 ? HiLinkModem.StatusDisconnected
            : string.Equals(Profiles.Single(p => p.Index == CurrentProfile).Apn, WorkingApn, StringComparison.OrdinalIgnoreCase) ? HiLinkModem.StatusConnected
            : 33;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath.TrimStart('/');
            if (path == "api/webserver/SesTokInfo")
                return Xml($"<response><SesInfo>SessionID=abc{_token}</SesInfo><TokInfo>token{++_token}</TokInfo></response>");

            if (!request.Headers.TryGetValues("Cookie", out var cookie) || !cookie.Single().StartsWith("SessionID=", StringComparison.Ordinal))
                return Error(125002);

            if (request.Method == HttpMethod.Post)
            {
                if (TokenErrorsToSend > 0)
                {
                    TokenErrorsToSend--;
                    return Error(125003);
                }
                if (LoginRequired)
                    return Error(100003);
                var body = XElement.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                Posts.Add($"{path} {body.ToString(SaveOptions.DisableFormatting)}");
                return Post(path, body);
            }

            return path switch
            {
                "api/monitoring/status" => Xml($"<response><ConnectionStatus>{ConnectionStatus}</ConnectionStatus><SignalIcon>3</SignalIcon><CurrentNetworkType>19</CurrentNetworkType><ServiceStatus>2</ServiceStatus><SimStatus>1</SimStatus><CurrentNetworkTypeEx>101</CurrentNetworkTypeEx></response>"),
                "api/device/basic_information" => Xml("<response><productfamily>LTE</productfamily><classify>hilink</classify><devicename>E3372</devicename></response>"),
                "api/net/current-plmn" => Xml("<response><State>0</State><FullName>Play</FullName><Numeric>26006</Numeric></response>"),
                "api/device/signal" => Xml("<response><rsrq>-9dB</rsrq><rsrp>-104dBm</rsrp><rssi>-79dBm</rssi><sinr>-2dB</sinr><mode>7</mode></response>"),
                "api/pin/status" => Xml("<response><SimState>257</SimState><PinOptState>258</PinOptState></response>"),
                "api/dialup/mobile-dataswitch" => Xml($"<response><dataswitch>{DataSwitch}</dataswitch></response>"),
                "api/dialup/profiles" => Xml("<response><CurrentProfile>" + CurrentProfile + "</CurrentProfile><Profiles>"
                                             + string.Concat(Profiles.Select(p => $"<Profile><Index>{p.Index}</Index><IsValid>1</IsValid><Name>{p.Name}</Name><ApnIsStatic>1</ApnIsStatic><ApnName>{p.Apn}</ApnName><ReadOnly>{(p.ReadOnly ? 1 : 0)}</ReadOnly></Profile>"))
                                             + "</Profiles></response>"),
                _ => Error(100002),
            };
        }

        private HttpResponseMessage Post(string path, XElement body)
        {
            switch (path)
            {
                case "api/dialup/profiles":
                    var modify = (int)body.Element("Modify")!;
                    var profile = body.Element("Profile");
                    if (modify == 1)
                        Profiles.Add((Profiles.Max(p => p.Index) + 1, (string)profile!.Element("Name")!, (string)profile.Element("ApnName")!, false));
                    else if (modify == 2)
                    {
                        var index = (int)profile!.Element("Index")!;
                        var i = Profiles.FindIndex(p => p.Index == index);
                        Profiles[i] = Profiles[i] with { Apn = (string)profile.Element("ApnName")! };
                    }
                    var setDefault = (int)body.Element("SetDefault")!;
                    if (Profiles.Any(p => p.Index == setDefault))
                        CurrentProfile = setDefault;
                    return Xml("<response>OK</response>");
                case "api/dialup/mobile-dataswitch":
                    DataSwitch = (int)body.Element("dataswitch")!;
                    return Xml("<response>OK</response>");
                default:
                    return Error(100002);
            }
        }

        private static HttpResponseMessage Error(int code) => Xml($"<error><code>{code}</code><message></message></error>");

        private static HttpResponseMessage Xml(string body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + body, Encoding.UTF8, "text/xml"),
        };
    }

    private static HiLinkModem Modem(FakeStick stick) => new(HiLinkModem.DefaultAddress, new HiLinkModemOptions
    {
        ConnectWait = TimeSpan.FromSeconds(3),
        RedialPause = TimeSpan.Zero,
    }, stick);

    [Fact]
    public async Task Status_ShowsWhyTheStickHasNoData()
    {
        using var modem = Modem(new FakeStick());

        var status = await modem.ReadStatusAsync();

        Assert.False(status.Connected);
        Assert.Equal(33, status.ConnectionStatus);
        Assert.Contains("APN", status.ConnectionText);
        Assert.Equal("Play", status.Operator);
        Assert.Equal("LTE", status.NetworkType);
        Assert.Equal(-104, status.Rsrp);
        Assert.Equal(-2, status.Sinr);
        Assert.True(status.SimReady);
        Assert.True(status.MobileData);
        Assert.Equal("o2", status.ProfileName);
        Assert.Equal("internetn", status.Apn);
        Assert.Equal("E3372", status.DeviceName);
    }

    [Fact]
    public async Task EnsureApn_AddsAProfile_MakesItTheDefault_AndRedials()
    {
        var stick = new FakeStick();
        using var modem = Modem(stick);

        var result = await modem.EnsureApnAsync("internet");

        Assert.True(result.Changed);
        Assert.Equal("internetn", result.PreviousApn);
        Assert.Equal("itbees", result.ProfileName);
        Assert.True(result.Status.Connected, result.Status.ConnectionText);
        Assert.Equal(3, stick.CurrentProfile);
        Assert.Contains(stick.Posts, p => p.Contains("<dataswitch>0</dataswitch>"));
        Assert.Equal(1, stick.DataSwitch);
        Assert.Contains(stick.Profiles, p => p is { Name: "o2", Apn: "internetn" });
    }

    [Fact]
    public async Task EnsureApn_IsIdempotent()
    {
        var stick = new FakeStick();
        using var modem = Modem(stick);
        await modem.EnsureApnAsync("internet");
        stick.Posts.Clear();

        var again = await modem.EnsureApnAsync("INTERNET");

        Assert.False(again.Changed);
        Assert.Empty(stick.Posts);
        Assert.Equal(3, stick.Profiles.Count);
    }

    [Fact]
    public async Task EnsureApn_UpdatesItsOwnProfile_InsteadOfAddingAnother()
    {
        var stick = new FakeStick { WorkingApn = "plus" };
        stick.Profiles.Add((3, "itbees", "internet", false));
        using var modem = Modem(stick);

        var result = await modem.EnsureApnAsync("plus");

        Assert.True(result.Status.Connected);
        Assert.Equal(3, stick.Profiles.Count);
        Assert.Equal("plus", stick.Profiles.Single(p => p.Name == "itbees").Apn);
        Assert.Equal(3, stick.CurrentProfile);
    }

    [Fact]
    public async Task EnsureApn_PicksAnExistingProfileWithThatApn()
    {
        var stick = new FakeStick { WorkingApn = "broadband" };
        using var modem = Modem(stick);

        var result = await modem.EnsureApnAsync("broadband");

        Assert.Equal("Connect Mobile", result.ProfileName);
        Assert.Equal(1, stick.CurrentProfile);
        Assert.Equal(2, stick.Profiles.Count);
    }

    [Fact]
    public async Task TokenError_IsRetriedWithAFreshToken()
    {
        var stick = new FakeStick { TokenErrorsToSend = 1 };
        using var modem = Modem(stick);

        var result = await modem.EnsureApnAsync("internet");

        Assert.True(result.Status.Connected);
    }

    [Fact]
    public async Task StickWithALogin_GivesAClearError()
    {
        using var modem = Modem(new FakeStick { LoginRequired = true });

        var e = await Assert.ThrowsAsync<HiLinkException>(() => modem.EnsureApnAsync("internet"));

        Assert.Equal(100003, e.ErrorCode);
        Assert.Contains("login", e.Message);
    }

    [Theory]
    [InlineData("internet", true)]
    [InlineData("internet.t-mobile.pl", true)]
    [InlineData("", false)]
    [InlineData("int<x>", false)]
    [InlineData("has space", false)]
    public void Apn_IsValidated(string apn, bool valid) => Assert.Equal(valid, HiLinkModem.IsValidApn(apn));

    [Fact]
    public async Task NoStick_IsReportedAsUnreachable()
    {
        using var modem = new HiLinkModem("127.0.0.1:9", new HiLinkModemOptions { RequestTimeout = TimeSpan.FromSeconds(2) });

        await Assert.ThrowsAsync<HiLinkUnreachableException>(() => modem.ReadStatusAsync());
    }
}
