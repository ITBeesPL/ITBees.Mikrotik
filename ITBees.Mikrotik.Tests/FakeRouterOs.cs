using System.Net;
using System.Net.Sockets;
using ITBees.Mikrotik.Api;
using ITBees.Mikrotik.WireGuard;

namespace ITBees.Mikrotik.Tests;

/// <summary>
/// In-memory RouterOS API server: login (plain and legacy MD5), print with equality queries, add (with place-before),
/// set, remove, move, singleton menus and a factory-default RB960PGS state. Interface references are validated
/// like on a real router, so ordering mistakes (e.g. using a bridge before creating it) fail the tests.
/// </summary>
internal sealed class FakeRouterOs : IAsyncDisposable
{
    private static readonly HashSet<string> MenusReferencingInterface = new(StringComparer.Ordinal)
    {
        "/interface/list/member", "/interface/bridge/port", "/ip/address", "/ip/dhcp-client", "/ip/dhcp-server", "/interface/wireguard/peers",
    };

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;
    private readonly object _sync = new();
    private int _nextId = 0x100;

    private FakeRouterOs(IPAddress address, int port)
    {
        _listener = new TcpListener(address, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = AcceptLoopAsync();
    }

    public int Port { get; }

    public bool LegacyLogin { get; set; }

    /// <summary>Replaces the normal login result with a trap carrying this message.</summary>
    public string? LoginTrapMessage { get; set; }

    /// <summary>Answer prints without data with !empty (RouterOS 7.18+).</summary>
    public bool SendEmptyReplies { get; set; }

    public Dictionary<string, List<Dictionary<string, string>>> Tables { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, Dictionary<string, string>> Singletons { get; } = new(StringComparer.Ordinal);

    /// <summary>Write commands in order (path + attributes), for assertions.</summary>
    public List<string> WriteLog { get; } = new();

    /// <summary>Called after every applied write; lets tests check invariants on intermediate states.</summary>
    public Action<FakeRouterOs, string>? AfterWrite { get; set; }

    /// <summary>When it returns true for an applied command, the connection is closed without a reply.</summary>
    public Func<string, IReadOnlyDictionary<string, string>, bool>? DropConnectionAfter { get; set; }

    /// <summary>When true, APN profile changes do not reach the RouterOS-made LTE DHCP client until the modem reconnects.</summary>
    public bool ApnProfileAppliesOnReconnect { get; set; }

    public int Logins { get; private set; }

    public static FakeRouterOs Start(IPAddress? address = null, int port = 0) => new(address ?? IPAddress.Loopback, port);

    /// <summary>Factory-default hEX PoE (RB960PGS) with RouterOS 7, defconf and a Huawei E3372 (lte1).</summary>
    public static FakeRouterOs StartFactoryRb960(string password = "STICKER123", bool withLte = true, string version = "7.16.2 (stable)", IPAddress? address = null, int port = 0)
    {
        var fake = Start(address, port);
        fake.LoadFactoryState(password, withLte, version);
        return fake;
    }

    public MikrotikConnectionOptions Options(string password, string user = "admin") => new()
    {
        Host = "127.0.0.1",
        Port = Port,
        Username = user,
        Password = password,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        CommandTimeout = TimeSpan.FromSeconds(10),
    };

    public List<Dictionary<string, string>> Table(string menu)
    {
        lock (_sync)
            return Tables.TryGetValue(menu, out var rows) ? rows.Select(r => new Dictionary<string, string>(r)).ToList() : new List<Dictionary<string, string>>();
    }

    public Dictionary<string, string>? Row(string menu, string property, string value) =>
        Table(menu).FirstOrDefault(r => r.TryGetValue(property, out var v) && v == value);

    public string Snapshot()
    {
        lock (_sync)
        {
            var parts = Tables.OrderBy(t => t.Key).Select(t => t.Key + ":" + string.Join("|", t.Value.Select(r => string.Join(",", r.OrderBy(kv => kv.Key).Select(kv => kv.Key + "=" + kv.Value)))))
                .Concat(Singletons.OrderBy(s => s.Key).Select(s => s.Key + ":" + string.Join(",", s.Value.OrderBy(kv => kv.Key).Select(kv => kv.Key + "=" + kv.Value))));
            return string.Join("\n", parts);
        }
    }

    public string AddRow(string menu, Dictionary<string, string> row)
    {
        lock (_sync)
        {
            if (!Tables.TryGetValue(menu, out var rows))
                Tables[menu] = rows = new List<Dictionary<string, string>>();
            var id = row.TryGetValue(".id", out var existing) ? existing : NewId();
            row[".id"] = id;
            rows.Add(row);
            return id;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch
        {
            // Listener shutdown.
        }
        _stop.Dispose();
    }

    private string NewId() => "*" + (_nextId++).ToString("X");

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
            }
            catch
            {
                return;
            }
            _ = Task.Run(() => HandleClientAsync(client));
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        using (client)
        {
            var stream = client.GetStream();
            var loggedIn = false;
            string? challenge = null;
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var words = await RouterOsWordCodec.ReadSentenceAsync(stream, _stop.Token).ConfigureAwait(false);
                    if (words.Count == 0)
                        continue;
                    var path = words[0];
                    var attributes = new Dictionary<string, string>(StringComparer.Ordinal);
                    var queries = new List<(string, string)>();
                    string? tag = null;
                    foreach (var word in words.Skip(1))
                    {
                        if (word.StartsWith(".tag=", StringComparison.Ordinal))
                        {
                            tag = word[5..];
                        }
                        else if (word.StartsWith('='))
                        {
                            var i = word.IndexOf('=', 1);
                            attributes[i < 0 ? word[1..] : word[1..i]] = i < 0 ? string.Empty : word[(i + 1)..];
                        }
                        else if (word.StartsWith('?'))
                        {
                            var i = word.IndexOf('=');
                            queries.Add(i < 0 ? (word[1..], string.Empty) : (word[1..i], word[(i + 1)..]));
                        }
                    }

                    var replies = new List<List<string>>();
                    if (path == "/login")
                    {
                        loggedIn = HandleLogin(attributes, replies, ref challenge);
                    }
                    else if (!loggedIn)
                    {
                        replies.Add(new List<string> { "!fatal", "not logged in" });
                    }
                    else
                    {
                        Handle(path, attributes, queries, replies);
                    }

                    if (DropConnectionAfter?.Invoke(path, attributes) == true)
                        return;
                    foreach (var reply in replies)
                    {
                        if (tag != null && reply[0] != "!fatal")
                            reply.Add(".tag=" + tag);
                        await stream.WriteAsync(RouterOsWordCodec.EncodeSentence(reply), _stop.Token).ConfigureAwait(false);
                    }
                    if (replies.Any(r => r[0] == "!fatal"))
                        return;
                }
            }
            catch
            {
                // Client went away.
            }
        }
    }

    private bool HandleLogin(Dictionary<string, string> attributes, List<List<string>> replies, ref string? challenge)
    {
        attributes.TryGetValue("name", out var name);
        var user = Row("/user", "name", name ?? string.Empty);
        var expected = user?.GetValueOrDefault("password");

        if (LoginTrapMessage != null)
        {
            replies.Add(new List<string> { "!trap", "=message=" + LoginTrapMessage });
            replies.Add(new List<string> { "!done" });
            return false;
        }

        if (LegacyLogin)
        {
            if (!attributes.TryGetValue("response", out var response))
            {
                challenge = "0123456789abcdef0123456789abcdef";
                replies.Add(new List<string> { "!done", "=ret=" + challenge });
                return false;
            }
            if (expected != null && challenge != null && response == RouterOsApiConnection.LegacyLoginResponse(expected, challenge))
            {
                Logins++;
                replies.Add(new List<string> { "!done" });
                return true;
            }
        }
        else if (expected != null && attributes.TryGetValue("password", out var password) && password == expected)
        {
            Logins++;
            replies.Add(new List<string> { "!done" });
            return true;
        }

        replies.Add(new List<string> { "!trap", "=message=invalid user name or password (6)" });
        replies.Add(new List<string> { "!done" });
        return false;
    }

    private void Handle(string path, Dictionary<string, string> attributes, List<(string Name, string Value)> queries, List<List<string>> replies)
    {
        var slash = path.LastIndexOf('/');
        var menu = path[..slash];
        var verb = path[(slash + 1)..];
        lock (_sync)
        {
            try
            {
                switch (verb)
                {
                    case "print":
                        Print(menu, queries, replies);
                        break;
                    case "add":
                        var id = Add(menu, attributes);
                        replies.Add(new List<string> { "!done", "=ret=" + id });
                        break;
                    case "set":
                        Set(menu, attributes);
                        replies.Add(new List<string> { "!done" });
                        break;
                    case "remove":
                        Remove(menu, attributes);
                        replies.Add(new List<string> { "!done" });
                        break;
                    case "move":
                        Move(menu, attributes);
                        replies.Add(new List<string> { "!done" });
                        break;
                    default:
                        throw new TrapException("no such command");
                }
                if (verb is "add" or "set" or "remove" or "move")
                {
                    WriteLog.Add(path + " " + string.Join(" ", attributes.Select(kv => kv.Key + "=" + kv.Value)));
                    AfterWrite?.Invoke(this, path);
                }
            }
            catch (TrapException e)
            {
                replies.Clear();
                replies.Add(new List<string> { "!trap", "=message=" + e.Message });
                replies.Add(new List<string> { "!done" });
            }
        }
    }

    private void Print(string menu, List<(string Name, string Value)> queries, List<List<string>> replies)
    {
        IEnumerable<Dictionary<string, string>> rows;
        if (Singletons.TryGetValue(menu, out var singleton))
            rows = new[] { singleton };
        else if (Tables.TryGetValue(menu, out var table))
            rows = table.Where(r => queries.All(q => (r.TryGetValue(q.Name, out var v) ? v : string.Empty) == q.Value));
        else
            throw new TrapException("no such command prefix");

        var any = false;
        foreach (var row in rows)
        {
            any = true;
            var sentence = new List<string> { "!re" };
            sentence.AddRange(row.Where(kv => kv.Key != "password").Select(kv => $"={kv.Key}={kv.Value}"));
            replies.Add(sentence);
        }
        if (!any && SendEmptyReplies)
            replies.Add(new List<string> { "!empty" });
        replies.Add(new List<string> { "!done" });
    }

    private string Add(string menu, Dictionary<string, string> attributes)
    {
        if (!Tables.TryGetValue(menu, out var rows))
            throw new TrapException("no such command prefix");
        var row = new Dictionary<string, string>(attributes, StringComparer.Ordinal);
        row.Remove("place-before");
        ValidateInterfaceReference(menu, row);
        if (menu is "/interface/bridge" or "/interface/wireguard" && Tables["/interface"].Any(i => i["name"] == row["name"]))
            throw new TrapException("already have interface with such name");
        if (menu == "/interface/wireguard")
        {
            if (!row.ContainsKey("private-key"))
                row["private-key"] = WireGuardKeys.GeneratePrivateKey();
            row["public-key"] = WireGuardKeys.GetPublicKey(row["private-key"]);
        }
        if (menu == "/system/scheduler" && Singletons.TryGetValue("/system/device-mode", out var deviceMode) && deviceMode.GetValueOrDefault("scheduler") == "no")
            throw new TrapException("failure: not allowed by device-mode");
        if (menu == "/ip/dhcp-client")
        {
            if (rows.Any(r => r.GetValueOrDefault("interface") == row["interface"]))
                throw new TrapException("failure: dhcp-client on that interface already exists");
            // The site network (10.0.5.0/24) answers on ether1, or on the bridge once ether1 is one of its ports.
            var onSiteNetwork = row["interface"] == "ether1"
                                || Tables["/interface/bridge/port"].Any(p => p.GetValueOrDefault("interface") == "ether1" && p.GetValueOrDefault("bridge") == row["interface"]);
            row.TryAdd("status", onSiteNetwork ? "bound" : "searching...");
            if (onSiteNetwork)
            {
                row.TryAdd("address", "10.0.5.23/24");
                row.TryAdd("gateway", "10.0.5.1");
            }
        }

        var id = NewId();
        row[".id"] = id;
        if (attributes.TryGetValue("place-before", out var before))
        {
            var index = rows.FindIndex(r => r[".id"] == before);
            rows.Insert(index < 0 ? rows.Count : index, row);
        }
        else
        {
            rows.Add(row);
        }

        if (menu is "/interface/bridge" or "/interface/wireguard")
            Tables["/interface"].Add(new Dictionary<string, string> { [".id"] = NewId(), ["name"] = row["name"], ["type"] = menu == "/interface/bridge" ? "bridge" : "wg", ["running"] = "true" });
        return id;
    }

    private void Set(string menu, Dictionary<string, string> attributes)
    {
        if (Singletons.TryGetValue(menu, out var singleton))
        {
            foreach (var (k, v) in attributes)
                singleton[k] = v;
            return;
        }
        var row = Find(menu, attributes);
        if (row.GetValueOrDefault("dynamic") == "true")
            throw new TrapException("failure: can not change dynamic");
        foreach (var (k, v) in attributes)
        {
            if (k is ".id" or "numbers")
                continue;
            row[k] = v;
        }
        ValidateInterfaceReference(menu, row);
        if (menu == "/interface/wireguard" && attributes.ContainsKey("private-key"))
            row["public-key"] = WireGuardKeys.GetPublicKey(row["private-key"]);
        if (menu == "/interface/lte/apn" && !ApnProfileAppliesOnReconnect)
            ApplyApnProfileToDhcpClients(row);
    }

    /// <summary>
    /// RouterOS 7.17+ device-mode (/system/device-mode). "home" (factory mode of home routers) blocks the scheduler;
    /// "basic" and "advanced" allow it. Without this call the menu does not exist, as before 7.13.
    /// </summary>
    public void UseDeviceMode(string mode)
    {
        lock (_sync)
            Singletons["/system/device-mode"] = new() { ["mode"] = mode, ["scheduler"] = mode == "home" ? "no" : "yes", ["fetch"] = mode == "home" ? "no" : "yes", ["flagged"] = "no" };
    }

    /// <summary>
    /// RouterOS 7 with a HiLink (ECM) stick: the LTE interface gets a dynamic DHCP client that takes its route and DNS
    /// settings from the interface's APN profile and blocks any other DHCP client on lte1.
    /// </summary>
    public void AddRouterOsLteDhcpClient(string lte = "lte1")
    {
        lock (_sync)
        {
            var profileName = Tables["/interface/lte"].First(r => r["name"] == lte)["apn-profiles"].Split(',')[0];
            var profile = Tables["/interface/lte/apn"].First(r => r["name"] == profileName);
            profile.TryAdd("add-default-route", "yes");
            profile.TryAdd("default-route-distance", "2");
            profile.TryAdd("use-peer-dns", "yes");
            AddRow("/ip/dhcp-client", new()
            {
                ["interface"] = lte, ["dynamic"] = "true", ["disabled"] = "false", ["status"] = "bound", ["address"] = "192.168.8.100/24", ["gateway"] = "192.168.8.1",
            });
            ApplyApnProfileToDhcpClients(profile);
        }
    }

    private void ApplyApnProfileToDhcpClients(Dictionary<string, string> profile)
    {
        foreach (var modem in Tables["/interface/lte"].Where(m => m.GetValueOrDefault("apn-profiles")?.Split(',')[0] == profile["name"]))
        {
            foreach (var client in Tables["/ip/dhcp-client"].Where(c => c.GetValueOrDefault("interface") == modem["name"] && c.GetValueOrDefault("dynamic") == "true"))
            {
                foreach (var key in new[] { "add-default-route", "default-route-distance", "use-peer-dns" })
                {
                    if (profile.TryGetValue(key, out var value))
                        client[key] = value;
                }
            }
        }
    }

    private void Remove(string menu, Dictionary<string, string> attributes)
    {
        var row = Find(menu, attributes);
        Tables[menu].Remove(row);
        if (menu is "/interface/bridge" or "/interface/wireguard")
            Tables["/interface"].RemoveAll(i => i["name"] == row["name"]);
    }

    private void Move(string menu, Dictionary<string, string> attributes)
    {
        var rows = Tables.TryGetValue(menu, out var table) ? table : throw new TrapException("no such command prefix");
        var item = rows.FirstOrDefault(r => r[".id"] == attributes["numbers"]) ?? throw new TrapException("no such item");
        var destination = rows.FirstOrDefault(r => r[".id"] == attributes["destination"]) ?? throw new TrapException("no such item (destination)");
        rows.Remove(item);
        rows.Insert(rows.IndexOf(destination), item);
    }

    private Dictionary<string, string> Find(string menu, Dictionary<string, string> attributes)
    {
        if (!Tables.TryGetValue(menu, out var rows))
            throw new TrapException("no such command prefix");
        var key = attributes.TryGetValue(".id", out var id) ? id : attributes.TryGetValue("numbers", out var numbers) ? numbers : throw new TrapException("missing =.id=");
        return rows.FirstOrDefault(r => r[".id"] == key || (r.TryGetValue("name", out var name) && name == key)) ?? throw new TrapException("no such item");
    }

    private void ValidateInterfaceReference(string menu, Dictionary<string, string> row)
    {
        if (!MenusReferencingInterface.Contains(menu) || !row.TryGetValue("interface", out var name))
            return;
        if (!Tables["/interface"].Any(i => i["name"] == name))
            throw new TrapException($"input does not match any value of interface ({name})");
        if (menu == "/interface/bridge/port" && !Tables["/interface/bridge"].Any(b => b["name"] == row["bridge"]))
            throw new TrapException("input does not match any value of bridge");
        if (menu == "/interface/list/member" && !Tables["/interface/list"].Any(l => l["name"] == row["list"]))
            throw new TrapException("input does not match any value of list");
    }

    private void LoadFactoryState(string password, bool withLte, string version)
    {
        Singletons["/system/resource"] = new() { ["version"] = version, ["board-name"] = "hEX PoE", ["architecture-name"] = "mipsbe", ["uptime"] = "1h2m3s" };
        Singletons["/system/routerboard"] = new() { ["routerboard"] = "true", ["model"] = "RB960PGS", ["serial-number"] = "HEX0123456", ["current-firmware"] = "7.16.2" };
        Singletons["/system/identity"] = new() { ["name"] = "MikroTik" };
        Singletons["/system/clock"] = new() { ["time-zone-autodetect"] = "true", ["time-zone-name"] = "manual" };
        Singletons["/system/ntp/client"] = new() { ["enabled"] = "false", ["servers"] = string.Empty };
        Singletons["/ip/dns"] = new() { ["servers"] = string.Empty, ["allow-remote-requests"] = "true" };
        Singletons["/ip/neighbor/discovery-settings"] = new() { ["discover-interface-list"] = "LAN" };
        Singletons["/tool/mac-server"] = new() { ["allowed-interface-list"] = "LAN" };
        Singletons["/tool/mac-server/mac-winbox"] = new() { ["allowed-interface-list"] = "LAN" };
        Singletons["/tool/bandwidth-server"] = new() { ["enabled"] = "true" };
        Singletons["/ip/settings"] = new() { ["ip-forward"] = "true", ["send-redirects"] = "true", ["accept-redirects"] = "false" };

        foreach (var menu in new[]
                 {
                     "/interface", "/interface/bridge", "/interface/bridge/port", "/interface/list", "/interface/list/member", "/interface/wireguard",
                     "/interface/wireguard/peers", "/interface/lte", "/interface/lte/apn", "/ip/address", "/ipv6/address", "/ip/pool", "/ip/dhcp-server",
                     "/ip/dhcp-server/network", "/ip/dhcp-server/lease", "/ip/dhcp-client", "/ip/dns/static", "/ip/route", "/ip/firewall/filter",
                     "/ip/firewall/nat", "/ipv6/firewall/filter", "/ip/service", "/user", "/system/script", "/system/scheduler", "/tool/netwatch",
                     "/ip/firewall/service-port",
                 })
            Tables[menu] = new List<Dictionary<string, string>>();

        var mac = 0x22;
        foreach (var port in new[] { "ether1", "ether2", "ether3", "ether4", "ether5", "sfp1" })
            AddRow("/interface", new() { ["name"] = port, ["type"] = "ether", ["running"] = port is "ether1" or "ether2" ? "true" : "false", ["mac-address"] = $"4C:5E:0C:11:22:{mac++:X2}" });
        AddRow("/interface", new() { ["name"] = "bridge", ["type"] = "bridge", ["running"] = "true" });
        if (withLte)
        {
            AddRow("/interface", new() { ["name"] = "lte1", ["type"] = "lte", ["running"] = "true" });
            AddRow("/interface/lte", new() { ["name"] = "lte1", ["apn-profiles"] = "default" });
            AddRow("/interface/lte/apn", new() { ["name"] = "default", ["apn"] = "internet", ["default"] = "true" });
        }

        AddRow("/interface/bridge", new() { ["name"] = "bridge", ["comment"] = "defconf" });
        foreach (var port in new[] { "ether2", "ether3", "ether4", "ether5", "sfp1" })
            AddRow("/interface/bridge/port", new() { ["bridge"] = "bridge", ["interface"] = port, ["comment"] = "defconf" });
        AddRow("/interface/list", new() { ["name"] = "WAN", ["comment"] = "defconf" });
        AddRow("/interface/list", new() { ["name"] = "LAN", ["comment"] = "defconf" });
        AddRow("/interface/list/member", new() { ["list"] = "LAN", ["interface"] = "bridge", ["comment"] = "defconf" });
        AddRow("/interface/list/member", new() { ["list"] = "WAN", ["interface"] = "ether1", ["comment"] = "defconf" });

        AddRow("/ip/address", new() { ["address"] = "192.168.88.1/24", ["network"] = "192.168.88.0", ["interface"] = "bridge", ["comment"] = "defconf" });
        AddRow("/ip/address", new() { ["address"] = "10.0.5.23/24", ["network"] = "10.0.5.0", ["interface"] = "ether1", ["dynamic"] = "true" });
        AddRow("/ipv6/address", new() { ["address"] = "fe80::4e5e:cff:fe11:2223/64", ["interface"] = "bridge", ["dynamic"] = "true", ["link-local"] = "true" });
        AddRow("/ip/pool", new() { ["name"] = "default-dhcp", ["ranges"] = "192.168.88.10-192.168.88.254" });
        AddRow("/ip/dhcp-server", new() { ["name"] = "defconf", ["interface"] = "bridge", ["address-pool"] = "default-dhcp", ["lease-time"] = "30m", ["disabled"] = "false" });
        AddRow("/ip/dhcp-server/network", new() { ["address"] = "192.168.88.0/24", ["gateway"] = "192.168.88.1", ["dns-server"] = "192.168.88.1", ["comment"] = "defconf" });
        AddRow("/ip/dhcp-server/lease", new() { ["address"] = "192.168.88.254", ["mac-address"] = "AA:BB:CC:00:00:01", ["server"] = "defconf", ["dynamic"] = "true" });
        AddRow("/ip/dhcp-client", new()
        {
            ["interface"] = "ether1", ["comment"] = "defconf", ["disabled"] = "false", ["add-default-route"] = "yes", ["use-peer-dns"] = "yes",
            ["use-peer-ntp"] = "yes", ["status"] = "bound", ["address"] = "10.0.5.23/24", ["gateway"] = "10.0.5.1",
        });
        AddRow("/ip/dns/static", new() { ["name"] = "router.lan", ["address"] = "192.168.88.1", ["comment"] = "defconf" });
        AddRow("/ip/route", new() { ["dst-address"] = "0.0.0.0/0", ["gateway"] = "10.0.5.1", ["immediate-gw"] = "10.0.5.1%ether1", ["distance"] = "1", ["dynamic"] = "true", ["active"] = "true", ["routing-table"] = "main" });

        AddRow("/ip/firewall/filter", new() { ["chain"] = "forward", ["action"] = "passthrough", ["comment"] = "special dummy rule to show fasttrack counters", ["dynamic"] = "true" });
        AddDefconfRule("/ip/firewall/filter", "input", "accept", "defconf: accept established,related,untracked", ("connection-state", "established,related,untracked"));
        AddDefconfRule("/ip/firewall/filter", "input", "drop", "defconf: drop invalid", ("connection-state", "invalid"));
        AddDefconfRule("/ip/firewall/filter", "input", "accept", "defconf: accept ICMP", ("protocol", "icmp"));
        AddDefconfRule("/ip/firewall/filter", "input", "accept", "defconf: accept to local loopback (for CAPsMAN)", ("dst-address", "127.0.0.1"));
        AddDefconfRule("/ip/firewall/filter", "input", "drop", "defconf: drop all not coming from LAN", ("in-interface-list", "!LAN"));
        AddDefconfRule("/ip/firewall/filter", "forward", "fasttrack-connection", "defconf: fasttrack", ("connection-state", "established,related"));
        AddDefconfRule("/ip/firewall/filter", "forward", "accept", "defconf: accept established,related, untracked", ("connection-state", "established,related,untracked"));
        AddDefconfRule("/ip/firewall/filter", "forward", "drop", "defconf: drop invalid", ("connection-state", "invalid"));
        AddDefconfRule("/ip/firewall/filter", "forward", "drop", "defconf: drop all from WAN not DSTNATed", ("connection-nat-state", "!dstnat"), ("in-interface-list", "WAN"));
        AddDefconfRule("/ip/firewall/nat", "srcnat", "masquerade", "defconf: masquerade", ("out-interface-list", "WAN"), ("ipsec-policy", "out,none"));
        AddDefconfRule("/ipv6/firewall/filter", "input", "accept", "defconf: accept established,related,untracked", ("connection-state", "established,related,untracked"));
        AddDefconfRule("/ipv6/firewall/filter", "input", "drop", "defconf: drop everything else not coming from LAN", ("in-interface-list", "!LAN"));

        foreach (var (helper, ports) in new[] { ("ftp", "21"), ("sip", "5060,5061"), ("pptp", string.Empty) })
            AddRow("/ip/firewall/service-port", new() { ["name"] = helper, ["ports"] = ports, ["disabled"] = "false" });
        foreach (var (service, port) in new[] { ("telnet", "23"), ("ftp", "21"), ("www", "80"), ("ssh", "22"), ("www-ssl", "443"), ("api", "8728"), ("winbox", "8291"), ("api-ssl", "8729") })
            AddRow("/ip/service", new() { ["name"] = service, ["port"] = port, ["disabled"] = service == "www-ssl" ? "true" : "false" });
        AddRow("/user", new() { ["name"] = "admin", ["group"] = "full", ["password"] = password });
    }

    private void AddDefconfRule(string menu, string chain, string action, string comment, params (string, string)[] matchers)
    {
        var row = new Dictionary<string, string> { ["chain"] = chain, ["action"] = action, ["comment"] = comment, ["disabled"] = "false", ["dynamic"] = "false" };
        foreach (var (k, v) in matchers)
            row[k] = v;
        AddRow(menu, row);
    }

    private sealed class TrapException : Exception
    {
        public TrapException(string message)
            : base(message)
        {
        }
    }
}
