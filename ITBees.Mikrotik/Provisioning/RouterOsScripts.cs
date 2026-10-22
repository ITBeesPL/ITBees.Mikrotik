using System.Globalization;

namespace ITBees.Mikrotik.Provisioning;

/// <summary>RouterOS 7 scripts installed on the router. Kept small and defensive: they run unattended for years.</summary>
internal static class RouterOsScripts
{
    public const string WanCheckRoutePrefix = "itbees:wan-check-";
    public const string WanDefaultRoutePrefix = "itbees:wan-default-";
    public const string VpnPeerComment = "itbees:vpn-peer";
    public const string VpnWatchdogName = "itbees-vpn-watchdog";

    /// <summary>
    /// DHCP client script on the WAN port. The client does not add a default route itself (failover uses
    /// recursive routes); this script points the check-host routes at whatever gateway the site network hands out.
    /// </summary>
    public static string WanLeaseScript() =>
        """
        # itbees: keeps the failover check routes on the current WAN gateway (managed by ITBees.Mikrotik)
        :if ($bound=1) do={
          :local gw $"gateway-address"
          :foreach r in=[/ip route find where comment~"^itbees:wan-check-"] do={
            :do { /ip route set $r gateway=$gw } on-error={}
          }
          :log info ("itbees: WAN lease " . $"lease-address" . " gateway " . $gw)
        } else={
          :log warning "itbees: WAN lease lost"
        }
        """.Replace("\r", string.Empty);

    /// <summary>Netwatch script run when the primary uplink changes state.</summary>
    public static string UplinkChangedScript(bool up) =>
        (up
            ? ":log warning \"itbees: primary uplink restored - traffic returns to WAN\"\n"
            : ":log warning \"itbees: primary uplink check failed - traffic moves to LTE\"\n")
        + ":foreach c in=[/ip firewall connection find] do={ :do { /ip firewall connection remove $c } on-error={} }\n";

    /// <summary>
    /// Forces a new handshake when the tunnel has been quiet for too long by re-setting the endpoint address,
    /// which also re-resolves a DNS endpoint. (Disabling/enabling the peer is avoided: RouterOS 7.24 is reported
    /// not to reinstall a re-enabled peer.)
    /// </summary>
    public static string VpnWatchdogScript(int handshakeTimeoutSeconds)
    {
        var limit = TimeSpan.FromSeconds(handshakeTimeoutSeconds).ToString(@"hh\:mm\:ss", CultureInfo.InvariantCulture);
        return $$"""
            # itbees: WireGuard watchdog (managed by ITBees.Mikrotik)
            :foreach p in=[/interface wireguard peers find where comment="{{VpnPeerComment}}" && disabled=no] do={
              :local hs
              :do { :set hs [/interface wireguard peers get $p last-handshake] } on-error={}
              :local stale true
              :if ([:typeof $hs] = "time") do={ :if ($hs <= {{limit}}) do={ :set stale false } }
              :if ($stale) do={
                :local ep [/interface wireguard peers get $p endpoint-address]
                :log warning ("itbees: VPN handshake stale (" . [:tostr $hs] . "), re-resolving " . $ep)
                :do { /interface wireguard peers set $p endpoint-address=$ep } on-error={ :log error "itbees: VPN watchdog could not reset the peer" }
              }
            }
            """.Replace("\r", string.Empty);
    }
}
