using ITBees.Mikrotik.Api;

namespace ITBees.Mikrotik.Tests;

public class RouterOsApiTests
{
    [Theory]
    [InlineData(0, 1)]
    [InlineData(0x7F, 1)]
    [InlineData(0x80, 2)]
    [InlineData(0x3FFF, 2)]
    [InlineData(0x4000, 3)]
    [InlineData(0x1FFFFF, 3)]
    [InlineData(0x200000, 4)]
    [InlineData(0xFFFFFFF, 4)]
    [InlineData(0x10000000, 5)]
    public void LengthPrefix_RoundTrips_AtEncodingBoundaries(int length, int expectedSize)
    {
        var encoded = RouterOsWordCodec.EncodeLength(length);
        Assert.Equal(expectedSize, encoded.Length);

        if (length > RouterOsWordCodec.MaxWordLength)
        {
            Assert.Throws<FormatException>(() => RouterOsWordCodec.DecodeLength(encoded, out _));
            return;
        }
        Assert.Equal(expectedSize, RouterOsWordCodec.DecodeLength(encoded, out var decoded));
        Assert.Equal(length, decoded);
    }

    [Fact]
    public void LengthPrefix_UsesDocumentedBytes()
    {
        Assert.Equal(new byte[] { 0x80, 0x80 }, RouterOsWordCodec.EncodeLength(0x80));
        Assert.Equal(new byte[] { 0xC0, 0x40, 0x00 }, RouterOsWordCodec.EncodeLength(0x4000));
    }

    [Fact]
    public async Task Sentence_RoundTripsThroughStream()
    {
        var words = new[] { "/ip/address/add", "=address=10.0.0.1/24", "=comment=" + new string('x', 300), ".tag=7" };
        using var stream = new MemoryStream(RouterOsWordCodec.EncodeSentence(words));
        var read = await RouterOsWordCodec.ReadSentenceAsync(stream, CancellationToken.None);
        Assert.Equal(words, read);
    }

    [Fact]
    public void Reply_ParsesAttributesWithEqualsSignsInValues()
    {
        var reply = RouterOsReply.Parse(new[] { "!re", "=.id=*1", "=source=:if ($a=1) do={}", ".tag=3" });
        Assert.Equal(RouterOsReplyType.Data, reply.Type);
        Assert.Equal("3", reply.Tag);
        Assert.Equal(":if ($a=1) do={}", reply.Attributes["source"]);
    }

    [Fact]
    public void Command_ToCliString_MasksSecrets()
    {
        var cli = new RouterOsCommand("/user/set").With(".id", "*1").With("password", "Secret1!").With("comment", "parking gate").ToCliString();
        Assert.Equal("/user set numbers=*1 password=*** comment=\"parking gate\"", cli);
    }

    [Theory]
    [InlineData("25s", 25)]
    [InlineData("1m25s", 85)]
    [InlineData("00:03:00", 180)]
    [InlineData("1d2h", 93600)]
    [InlineData("1w", 604800)]
    [InlineData("3w2d10:00:01", 2023201)]
    public void Durations_AreParsed(string text, int seconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(seconds), RouterOsValues.ParseDuration(text));
    }

    [Theory]
    [InlineData("true", "yes", true)]
    [InlineData("false", "no", true)]
    [InlineData("00:00:25", "25s", true)]
    [InlineData("1.1.1.1, 8.8.8.8", "1.1.1.1,8.8.8.8", true)]
    [InlineData("8.8.8.8,1.1.1.1", "1.1.1.1,8.8.8.8", false)]
    [InlineData(null, "", true)]
    [InlineData("ether1", "ether2", false)]
    public void Values_AreComparedTolerantly(string? current, string desired, bool equal)
    {
        Assert.Equal(equal, RouterOsValues.AreEquivalent(current, desired));
    }

    [Fact]
    public void Version_IsParsed()
    {
        Assert.True(RouterOsVersion.TryParse("7.16.2 (stable)", out var v));
        Assert.Equal((7, 16, 2), (v.Major, v.Minor, v.Patch));
        Assert.Equal("stable", v.Channel);
        Assert.True(RouterOsVersion.TryParse("7.19beta3 (testing)", out var beta));
        Assert.Equal(19, beta.Minor);
        Assert.False(v.IsAtLeast(7, 17));
    }

    [Fact]
    public async Task Login_WithPassword_Succeeds_AndReadsDeviceInfo()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        await using var client = await MikrotikClient.ConnectAsync(fake.Options(TestData.FactoryPassword));

        Assert.True(client.IsConnected);
        Assert.Equal("RB960PGS", client.Device.Model);
        Assert.Equal("hEX PoE", client.Device.BoardName);
        Assert.Equal(7, client.Device.Version.Major);
    }

    [Fact]
    public async Task Login_WithWrongPassword_ThrowsAuthenticationException()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        var e = await Assert.ThrowsAsync<MikrotikAuthenticationException>(() => MikrotikClient.ConnectAsync(fake.Options("wrong")));
        Assert.Contains("invalid user name or password", e.RouterMessage);
    }

    [Fact]
    public async Task Login_Legacy_Md5Challenge_Succeeds()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        fake.LegacyLogin = true;
        await using var client = await MikrotikClient.ConnectAsync(fake.Options(TestData.FactoryPassword));
        Assert.Equal(1, fake.Logins);
    }

    [Fact]
    public async Task Login_ExpiredPassword_IsReportedSeparately()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        fake.LoginTrapMessage = "password expired, change it first";
        await Assert.ThrowsAsync<MikrotikPasswordExpiredException>(() => MikrotikClient.ConnectAsync(fake.Options(TestData.FactoryPassword)));
    }

    [Fact]
    public async Task Connect_ToClosedPort_ThrowsConnectionException()
    {
        int port;
        await using (var fake = FakeRouterOs.Start())
            port = fake.Port;
        var options = new MikrotikConnectionOptions { Host = "127.0.0.1", Port = port, Password = "x", ConnectTimeout = TimeSpan.FromSeconds(2) };
        await Assert.ThrowsAsync<MikrotikConnectionException>(() => MikrotikClient.ConnectAsync(options));
    }

    [Fact]
    public async Task Trap_BecomesCommandException_AndSessionStaysUsable()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        await using var client = await MikrotikClient.ConnectAsync(fake.Options(TestData.FactoryPassword));

        var e = await Assert.ThrowsAsync<MikrotikCommandException>(() => client.ExecuteAsync(new RouterOsCommand("/ip/address/remove").With(".id", "*FFFF")));
        Assert.Equal("no such item", e.RouterMessage);

        var addresses = await client.PrintAsync("/ip/address", ("interface", "bridge"));
        Assert.Single(addresses);
        Assert.Equal("192.168.88.1/24", addresses[0].Get("address"));
    }

    [Fact]
    public async Task EmptyReply_FromRouterOs718_IsHandled()
    {
        await using var fake = FakeRouterOs.StartFactoryRb960();
        fake.SendEmptyReplies = true;
        await using var client = await MikrotikClient.ConnectAsync(fake.Options(TestData.FactoryPassword));
        var rows = await client.PrintAsync("/interface/wireguard");
        Assert.Empty(rows);
    }
}
