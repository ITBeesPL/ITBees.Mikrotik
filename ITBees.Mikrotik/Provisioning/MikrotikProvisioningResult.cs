namespace ITBees.Mikrotik.Provisioning;

public sealed class MikrotikProvisioningOptions
{
    /// <summary>Only read the router and report the commands that would be sent.</summary>
    public bool DryRun { get; set; }

    /// <summary>
    /// Allow applying a package over the WAN (site network) or LTE. Off by default: the managed firewall closes
    /// those interfaces, so the session would be cut mid-way. Connect to a LAN port or over the VPN instead.
    /// </summary>
    public bool AllowManagementOverWan { get; set; }

    /// <summary>Log in again with the new password on a second session before relying on it (restores the old one on failure).</summary>
    public bool VerifyNewPassword { get; set; } = true;

    /// <summary>
    /// Router address of this session as the router sees it. Detected automatically; set it only when the
    /// session goes through NAT or a port forward.
    /// </summary>
    public string? SessionRouterAddress { get; set; }

    /// <summary>How long to wait for a reply to the final LAN re-addressing command (the session usually drops).</summary>
    public TimeSpan LanSwitchReplyTimeout { get; set; } = TimeSpan.FromSeconds(5);
}

public enum MikrotikChangeAction
{
    Add,
    Set,
    Remove,
    Move,
}

/// <summary>One write sent to the router (or planned, in a dry run).</summary>
public sealed record MikrotikConfigurationChange(string Step, MikrotikChangeAction Action, string Menu, string Description, string Command)
{
    public override string ToString() => $"[{Step}] {Description}: {Command}";
}

public enum ProvisioningStepStatus
{
    /// <summary>The router already matched the package.</summary>
    Unchanged,

    Changed,

    /// <summary>Not applicable (e.g. LTE modem not plugged in, VPN disabled and absent).</summary>
    Skipped,

    Failed,

    /// <summary>Not executed because an earlier step failed.</summary>
    NotRun,
}

public sealed record ProvisioningStepResult(string Name, ProvisioningStepStatus Status, int ChangeCount, string? Message)
{
    public override string ToString() => $"{Name}: {Status}{(ChangeCount > 0 ? $" ({ChangeCount} change(s))" : string.Empty)}{(Message != null ? " - " + Message : string.Empty)}";
}

/// <summary>Outcome of applying a configuration package.</summary>
public sealed class MikrotikProvisioningResult
{
    public bool Success { get; internal set; }

    public bool DryRun { get; internal set; }

    /// <summary>First error that stopped the run.</summary>
    public string? Error { get; internal set; }

    public MikrotikDeviceInfo? Device { get; internal set; }

    public List<ProvisioningStepResult> Steps { get; } = new();

    public List<MikrotikConfigurationChange> Changes { get; } = new();

    public List<string> Warnings { get; } = new();

    /// <summary>Address the site network (operator) gave ether1 over DHCP, e.g. "192.168.1.57/24".</summary>
    public string? WanAddress { get; internal set; }

    public string? WanGateway { get; internal set; }

    /// <summary>DHCP state of the WAN client: bound, searching, ...</summary>
    public string? WanStatus { get; internal set; }

    public bool LteDetected { get; internal set; }

    /// <summary>True when the new password was set (and verified) on the router.</summary>
    public bool PasswordChanged { get; internal set; }

    public string? VpnInterface { get; internal set; }

    /// <summary>Public key of the router's WireGuard interface; register it on the hub.</summary>
    public string? VpnPublicKey { get; internal set; }

    public string? VpnAddress { get; internal set; }

    /// <summary>The peer to add on the VPN hub (tunnel IP and, if allowed, the parking LAN).</summary>
    public WireGuard.WireGuardHubPeer? VpnHubPeer { get; internal set; }

    /// <summary>Router LAN address after the run.</summary>
    public string? LanRouterAddress { get; internal set; }

    /// <summary>
    /// The session used the old LAN address, which was replaced as the last step: reconnect using
    /// <see cref="LanRouterAddress"/> (after the computer renews its DHCP lease), the IPv6 link-local
    /// address or the VPN address.
    /// </summary>
    public bool ReconnectRequired { get; internal set; }

    public int ChangeCount => Changes.Count;

    public override string ToString() =>
        $"{(DryRun ? "DRY RUN " : string.Empty)}{(Success ? "OK" : "FAILED: " + Error)}; {ChangeCount} change(s); WAN {WanAddress ?? "-"}; VPN {VpnAddress ?? "-"}";
}
