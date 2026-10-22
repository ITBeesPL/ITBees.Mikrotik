namespace ITBees.Mikrotik;

/// <summary>How to reach and log in to one router over the RouterOS API.</summary>
public sealed class MikrotikConnectionOptions
{
    public const int DefaultApiPort = 8728;
    public const int DefaultApiSslPort = 8729;

    /// <summary>
    /// Router address: IPv4 ("192.168.88.1"), IPv6 with scope ("fe80::4e5e:cff:fe11:2233%en0" or "%12") or a DNS name.
    /// </summary>
    public string Host { get; set; } = string.Empty;

    /// <summary>API port; defaults to 8728 (plain) or 8729 (TLS).</summary>
    public int? Port { get; set; }

    public string Username { get; set; } = "admin";

    public string Password { get; set; } = string.Empty;

    /// <summary>Use api-ssl (8729). Requires a certificate assigned to the api-ssl service on the router.</summary>
    public bool UseTls { get; set; }

    /// <summary>Accept self-signed router certificates (typical for api-ssl). Only relevant with <see cref="UseTls"/>.</summary>
    public bool AcceptAnyCertificate { get; set; } = true;

    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Maximum time for one command; the connection is closed when exceeded (its state is unknown).</summary>
    public TimeSpan CommandTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public int EffectivePort => Port ?? (UseTls ? DefaultApiSslPort : DefaultApiPort);

    public MikrotikConnectionOptions Clone() => (MikrotikConnectionOptions)MemberwiseClone();
}
