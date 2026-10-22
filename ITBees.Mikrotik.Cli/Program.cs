using ITBees.Mikrotik;
using ITBees.Mikrotik.Configuration;
using ITBees.Mikrotik.Discovery;
using ITBees.Mikrotik.Provisioning;
using ITBees.Mikrotik.Status;
using ITBees.Mikrotik.WireGuard;
using Microsoft.Extensions.Logging;

// Installer / bench tool for parking routers. Passwords can also come from MIKROTIK_PASSWORD.

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintUsage();
    return 0;
}

var options = Options.Parse(args.Skip(1));
using var loggerFactory = LoggerFactory.Create(builder => builder.AddProvider(new ConsoleLoggerProvider(options.Has("verbose") ? LogLevel.Debug : LogLevel.Information)));
var service = new MikrotikService(loggerFactory);

try
{
    switch (args[0].ToLowerInvariant())
    {
        case "discover":
        {
            var neighbors = await service.DiscoverAsync(new MndpDiscoveryOptions { Duration = TimeSpan.FromSeconds(options.Int("seconds", 5)) });
            Console.WriteLine($"{"MAC",-18} {"Identity",-24} {"Board",-12} {"RouterOS",-18} {"IPv4",-16} {"Local NIC",-10} Connect via");
            foreach (var n in neighbors)
                Console.WriteLine($"{n.MacAddressText,-18} {n.Identity,-24} {n.Board,-12} {n.Version,-18} {n.Ipv4Address?.ToString() ?? "-",-16} {n.LocalInterfaceName ?? "?",-10} {string.Join(" | ", n.GetConnectionCandidates())}");
            Console.WriteLine($"Found: {neighbors.Count}");
            return 0;
        }
        case "find":
        {
            var scan = await service.FindAndLoginAsync(ScanOptions(options), new MndpDiscoveryOptions { Duration = TimeSpan.FromSeconds(options.Int("seconds", 5)) });
            await using var client = scan.Client;
            PrintAttempts(scan.Attempts);
            Console.WriteLine($"Logged in: {scan.Device} as {scan.Credentials.Username} on {client.Host}");
            Console.WriteLine(client.Device);
            PrintStatus(await service.GetStatusAsync(client));
            return 0;
        }
        case "status":
        {
            await using var client = await ConnectAsync(options);
            PrintStatus(await service.GetStatusAsync(client, LoadPackage(options, required: false)));
            return 0;
        }
        case "apply":
        {
            var package = LoadPackage(options, required: true)!;
            var provisioning = new MikrotikProvisioningOptions { DryRun = options.Has("dry-run"), AllowManagementOverWan = options.Has("allow-wan") };
            MikrotikProvisioningResult result;
            if (options.Get("host") != null)
            {
                await using var client = await ConnectAsync(options);
                result = await service.ApplyConfigurationAsync(client, package, provisioning);
            }
            else
            {
                var setup = await service.SetupAsync(new MikrotikSetupRequest
                {
                    Credentials = ScanOptions(options).Credentials,
                    Package = package,
                    Provisioning = provisioning,
                    Filter = options.Get("mac") is { } mac ? n => n.MacAddressText.Equals(MikrotikNeighborMac(mac), StringComparison.OrdinalIgnoreCase) : null,
                });
                Console.WriteLine($"Router: {setup.Device} (login {setup.Username})");
                result = setup.Provisioning;
            }
            PrintResult(result);
            return result.Success ? 0 : 2;
        }
        case "sample-package":
            Console.WriteLine(SamplePackage().ToJson());
            return 0;
        case "validate":
        {
            var validation = LoadPackage(options, required: true)!.Validate();
            foreach (var error in validation.Errors)
                Console.WriteLine("ERROR   " + error);
            foreach (var warning in validation.Warnings)
                Console.WriteLine("WARNING " + warning);
            Console.WriteLine(validation.IsValid ? "Package is valid." : "Package is invalid.");
            return validation.IsValid ? 0 : 2;
        }
        case "wg-keys":
        {
            var pair = WireGuardKeys.GenerateKeyPair();
            Console.WriteLine($"PrivateKey   = {pair.PrivateKey}");
            Console.WriteLine($"PublicKey    = {pair.PublicKey}");
            Console.WriteLine($"PresharedKey = {WireGuardKeys.GeneratePresharedKey()}");
            return 0;
        }
        default:
            Console.Error.WriteLine($"Unknown command '{args[0]}'.");
            PrintUsage();
            return 1;
    }
}
catch (MikrotikDeviceNotFoundException e)
{
    Console.Error.WriteLine(e.Message);
    PrintAttempts(e.Attempts);
    return 3;
}
catch (MikrotikConfigurationException e)
{
    foreach (var error in e.Errors)
        Console.Error.WriteLine("ERROR " + error);
    return 2;
}
catch (MikrotikException e)
{
    Console.Error.WriteLine($"{e.GetType().Name}: {e.Message}");
    return 3;
}
catch (ArgumentException e)
{
    Console.Error.WriteLine(e.Message);
    return 1;
}

static string MikrotikNeighborMac(string mac) =>
    string.Join(":", LinkLocal.ParseMac(mac).GetAddressBytes().Select(b => b.ToString("X2")));

static MikrotikLoginScanOptions ScanOptions(Options options)
{
    var user = options.Get("user") ?? "admin";
    var passwords = options.All("password").ToList();
    if (passwords.Count == 0 && Environment.GetEnvironmentVariable("MIKROTIK_PASSWORD") is { Length: > 0 } fromEnv)
        passwords.Add(fromEnv);
    if (passwords.Count == 0)
        throw new ArgumentException("Give at least one --password (e.g. the sticker password); repeat it to try several.");
    var scan = new MikrotikLoginScanOptions();
    foreach (var password in passwords)
        scan.Credentials.Add(new MikrotikCredentials(user, password));
    return scan;
}

async Task<IMikrotikClient> ConnectAsync(Options o)
{
    var password = o.Get("password") ?? Environment.GetEnvironmentVariable("MIKROTIK_PASSWORD")
                   ?? throw new ArgumentException("--password is required (or MIKROTIK_PASSWORD).");
    return await service.ConnectAsync(new MikrotikConnectionOptions
    {
        Host = o.Get("host") ?? throw new ArgumentException("--host is required."),
        Port = o.Get("port") is { } port ? int.Parse(port) : null,
        UseTls = o.Has("tls"),
        Username = o.Get("user") ?? "admin",
        Password = password,
    });
}

static MikrotikConfigurationPackage? LoadPackage(Options options, bool required)
{
    var path = options.Get("package");
    if (path == null)
        return required ? throw new ArgumentException("--package <file.json> is required (see: mikrotik sample-package).") : null;
    return MikrotikConfigurationPackage.FromJson(File.ReadAllText(path));
}

static MikrotikConfigurationPackage SamplePackage()
{
    var router = WireGuardKeys.GenerateKeyPair();
    return new MikrotikConfigurationPackage
    {
        Identity = "octopark-parking-001",
        Security = { AdminPassword = "<new admin password, min. 8 characters>" },
        Lan =
        {
            Address = "10.64.1.1/24",
            Dhcp = { StaticLeases = { new StaticLease { MacAddress = "00:11:22:33:44:55", Address = "10.64.1.20", Comment = "barrier entry" } } },
        },
        Vpn =
        {
            Enabled = true,
            Address = "10.250.0.11/16",
            PrivateKey = router.PrivateKey,
            ServerPublicKey = "<hub public key>",
            ServerEndpoint = "vpn.example.com",
        },
    };
}

static void PrintAttempts(IEnumerable<MikrotikLoginAttempt> attempts)
{
    foreach (var attempt in attempts)
        Console.WriteLine("  " + attempt);
}

static void PrintStatus(MikrotikStatus status)
{
    Console.WriteLine($"Router:  {status.Device}");
    Console.WriteLine($"Uplink:  {status.ActiveUplink} via {status.ActiveGateway ?? "-"}");
    Console.WriteLine($"WAN:     {status.Wan.Interface} {(status.Wan.Running ? "link up" : "link down")}, DHCP {status.Wan.DhcpStatus ?? "-"}, address {status.Wan.Address ?? "-"}, gateway {status.Wan.Gateway ?? "-"}");
    Console.WriteLine(status.Lte.Detected
        ? $"LTE:     {status.Lte.Interface} {(status.Lte.Running ? "up" : "down")}, address {status.Lte.Address ?? "-"}, {status.Lte.Operator ?? ""} {status.Lte.AccessTechnology ?? ""} RSRP {status.Lte.Rsrp?.ToString() ?? "-"}"
        : $"LTE:     {status.Lte.Interface} not detected");
    Console.WriteLine(status.Vpn.Configured
        ? $"VPN:     {status.Vpn.Interface} {(status.Vpn.IsConnected ? "CONNECTED" : "NOT CONNECTED")}, {status.Vpn.Address}, endpoint {status.Vpn.Endpoint}, last handshake {status.Vpn.LastHandshake?.ToString() ?? "never"}"
        : "VPN:     not configured");
}

static void PrintResult(MikrotikProvisioningResult result)
{
    foreach (var step in result.Steps)
        Console.WriteLine($"  {step}");
    foreach (var change in result.Changes)
        Console.WriteLine($"    {change}");
    foreach (var warning in result.Warnings)
        Console.WriteLine($"WARNING {warning}");
    Console.WriteLine(result);
    if (result.VpnHubPeer != null)
    {
        Console.WriteLine();
        Console.WriteLine("Add this peer on the VPN hub (/etc/wireguard/wg0.conf):");
        Console.WriteLine(result.VpnHubPeer.ToWgQuickSection());
    }
    if (result.ReconnectRequired)
        Console.WriteLine($"The router now answers at {result.LanRouterAddress}. Renew this computer's DHCP lease before reconnecting.");
}

static void PrintUsage()
{
    Console.WriteLine("""
        mikrotik - parking router installer (ITBees.Mikrotik)

          discover [--seconds 5]                          list MikroTik routers on this network (MNDP, any IP addressing)
          find --password <p> [--password <p2>] [--user admin]
                                                          find the router that accepts the credentials, show its status
          status --host <ip> --password <p> [--package f.json]
          apply --package f.json --password <sticker> [--password <p2>] [--mac <mac>] [--dry-run]
                                                          discover + log in + apply (repeat --password to try several)
          apply --package f.json --host <ip> --password <p> [--dry-run] [--allow-wan]
          validate --package f.json
          sample-package                                  print an example configuration package (JSON)
          wg-keys                                         generate a WireGuard key pair and preshared key

        Common: --user <name> (default admin), --port <n>, --tls, --verbose. Password also from MIKROTIK_PASSWORD.
        Connect this computer to a LAN port (ether2-ether5) of the router.
        """);
}

internal sealed class Options
{
    private readonly List<(string Name, string? Value)> _values = new();

    public static Options Parse(IEnumerable<string> args)
    {
        var options = new Options();
        var list = args.ToList();
        for (var i = 0; i < list.Count; i++)
        {
            if (!list[i].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException($"Unexpected argument '{list[i]}'.");
            var name = list[i][2..];
            string? value = null;
            if (i + 1 < list.Count && !list[i + 1].StartsWith("--", StringComparison.Ordinal))
                value = list[++i];
            options._values.Add((name, value));
        }
        return options;
    }

    public bool Has(string name) => _values.Any(v => v.Name == name);

    public string? Get(string name) => _values.LastOrDefault(v => v.Name == name).Value;

    public IEnumerable<string> All(string name) => _values.Where(v => v.Name == name && v.Value != null).Select(v => v.Value!);

    public int Int(string name, int fallback) => Get(name) is { } value ? int.Parse(value) : fallback;
}

internal sealed class ConsoleLoggerProvider : ILoggerProvider
{
    private readonly LogLevel _minimum;

    public ConsoleLoggerProvider(LogLevel minimum)
    {
        _minimum = minimum;
    }

    public ILogger CreateLogger(string categoryName) => new ConsoleLogger(_minimum);

    public void Dispose()
    {
    }

    private sealed class ConsoleLogger : ILogger
    {
        private readonly LogLevel _minimum;

        public ConsoleLogger(LogLevel minimum)
        {
            _minimum = minimum;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= _minimum;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
                Console.Error.WriteLine($"{DateTime.Now:HH:mm:ss} {logLevel.ToString()[..4].ToUpperInvariant()} {formatter(state, exception)}");
        }
    }
}
