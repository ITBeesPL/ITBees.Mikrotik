namespace ITBees.Mikrotik;

/// <summary>Base exception for MikroTik communication and provisioning errors.</summary>
public class MikrotikException : Exception
{
    public MikrotikException(string? host, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Host = host;
    }

    /// <summary>Router address the error refers to (null when not tied to one router).</summary>
    public string? Host { get; }
}

/// <summary>The router could not be reached or the connection broke (timeout, refused, reset, !fatal).</summary>
public sealed class MikrotikConnectionException : MikrotikException
{
    public MikrotikConnectionException(string? host, string message, Exception? innerException = null, bool isTimeout = false)
        : base(host, message, innerException)
    {
        IsTimeout = isTimeout;
    }

    /// <summary>True when the router did not answer in time (as opposed to refusing or dropping the connection).</summary>
    public bool IsTimeout { get; }
}

/// <summary>The router rejected the user name or password.</summary>
public class MikrotikAuthenticationException : MikrotikException
{
    public MikrotikAuthenticationException(string? host, string message, string? routerMessage = null)
        : base(host, message)
    {
        RouterMessage = routerMessage;
    }

    /// <summary>Raw message returned by RouterOS, e.g. "invalid user name or password (6)".</summary>
    public string? RouterMessage { get; }
}

/// <summary>
/// The router accepted the credentials but requires a password change first
/// (factory-reset devices with an expired default password).
/// </summary>
public sealed class MikrotikPasswordExpiredException : MikrotikAuthenticationException
{
    public MikrotikPasswordExpiredException(string? host, string message, string? routerMessage = null)
        : base(host, message, routerMessage)
    {
    }
}

/// <summary>RouterOS answered a command with !trap (invalid value, missing item, no such command, ...).</summary>
public sealed class MikrotikCommandException : MikrotikException
{
    public MikrotikCommandException(string? host, string command, string routerMessage, int? category = null)
        : base(host, $"RouterOS rejected '{command}': {routerMessage}")
    {
        Command = command;
        RouterMessage = routerMessage;
        Category = category;
    }

    /// <summary>The command in CLI notation with secrets masked.</summary>
    public string Command { get; }

    /// <summary>The =message= of the !trap reply.</summary>
    public string RouterMessage { get; }

    /// <summary>The =category= of the !trap reply (0 missing item, 1 argument value failure, 2 execution interrupted, 3 scripting failure, 4 general failure, 5 API failure, 6 TTY failure, 7 :return value).</summary>
    public int? Category { get; }
}

/// <summary>The router answered with something the client does not understand.</summary>
public sealed class MikrotikProtocolException : MikrotikException
{
    public MikrotikProtocolException(string? host, string message, Exception? innerException = null)
        : base(host, message, innerException)
    {
    }
}

/// <summary>The configuration package is invalid; nothing was sent to the router.</summary>
public sealed class MikrotikConfigurationException : MikrotikException
{
    public MikrotikConfigurationException(IReadOnlyList<string> errors)
        : base(null, "Invalid MikroTik configuration package: " + string.Join(" | ", errors))
    {
        Errors = errors;
    }

    public IReadOnlyList<string> Errors { get; }
}

/// <summary>No discovered router accepted any of the given credentials.</summary>
public sealed class MikrotikDeviceNotFoundException : MikrotikException
{
    public MikrotikDeviceNotFoundException(string message, IReadOnlyList<Discovery.MikrotikLoginAttempt> attempts)
        : base(null, message)
    {
        Attempts = attempts;
    }

    /// <summary>Every login attempt with its outcome, for diagnostics.</summary>
    public IReadOnlyList<Discovery.MikrotikLoginAttempt> Attempts { get; }
}
