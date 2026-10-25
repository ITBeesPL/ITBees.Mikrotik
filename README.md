# ITBees.Mikrotik

Biblioteka .NET 8 do przygotowania routerów **MikroTik RB960PGS (hEX PoE)** dla parkingów Octopark:
fabrycznie nowy router + modem **Huawei E3372** w USB → skonfigurowany router parkingowy z własnym LAN-em,
automatycznym przełączaniem internetu (łącze podstawowe ↔ LTE) i stałym tunelem VPN do naszego serwera.

| Obszar | API |
|---|---|
| Lista MikroTików w sieci (MNDP, jak Winbox — niezależnie od adresacji IP) | `IMikrotikService.DiscoverAsync()` |
| Znalezienie routera, który przyjmuje podany login/hasło (np. hasło z naklejki) | `FindAndLoginAsync()`, `MikrotikLoginScanner` |
| Wszystko naraz: discovery → logowanie → konfiguracja | `SetupAsync(MikrotikSetupRequest)` |
| Zastosowanie pakietu konfiguracyjnego (idempotentnie, z trybem „dry run”) | `ApplyConfigurationAsync()`, `MikrotikProvisioner` |
| Status: adres od operatora, aktywne łącze, LTE, stan VPN | `GetStatusAsync()` → `MikrotikStatus` |
| Klucze WireGuard (X25519) i konfiguracja huba VPN | `WireGuardKeys`, `WireGuardHubPeer`, `WireGuardHubConfig` |
| Surowe API RouterOS (dowolna komenda) | `IMikrotikClient.ExecuteAsync(new RouterOsCommand(...))` |

Wymagania: RouterOS **7.x** na routerze (nowe RB960PGS mają v7; WireGuard jest tylko w v7). Komunikacja przez
**RouterOS API** (TCP 8728, opcjonalnie TLS 8729) po IPv4 albo IPv6 link-local.

## Docelowa konfiguracja routera

```
                 sieć klienta / operatora (DHCP)                         LTE (karta SIM)
                           │                                                  │
                        ether1  ── łącze podstawowe                 Huawei E3372 (USB, lte1) ── łącze zapasowe
                           │                                                  │
                    ┌──────┴──────────────────── RB960PGS ────────────────────┴─────┐
                    │  trasy failover: 1.0.0.1 / 208.67.222.222 sprawdzane co 10 s   │
                    │  przez ether1; gdy nie odpowiadają → ruch idzie przez LTE      │
                    │  WireGuard wg-octopark ──────────────► hub VPN (10.250.0.1)    │
                    └──────┬───────────────────────────────────────────────────────┘
                     bridge: ether2–ether5 (PoE out) + sfp1
                           │
          LAN parkingu, np. 10.64.12.0/24: szlabany, kamery, terminale, moduły I/O
          (DHCP z routera, stałe adresy dla urządzeń z pakietu)
```

Co dokładnie ustawia pakiet (kolejność kroków jest celowa — patrz „Bezpieczeństwo zmian”):

1. **Preflight** – wersja RouterOS ≥ 7, istnienie portów, wykrycie modemu `lte1`, sprawdzenie którędy idzie
   sesja (odmowa, jeśli przez WAN/LTE), konflikt adresacji LAN z siecią klienta.
2. **System** – nazwa (identity), strefa czasowa `Europe/Warsaw`, NTP.
3. **Bridge LAN** – `bridge` z portami ether2–ether5 i sfp1; usuwa z bridge’a porty spoza pakietu oraz WAN/LTE.
4. **Listy interfejsów** – `WAN` = ether1 + lte1, `LAN` = bridge, `VPN` = interfejs WireGuard.
5. **DNS** – stałe serwery (domyślnie 1.1.1.1, 8.8.8.8), router odpowiada na DNS dla LAN-u.
6. **LTE** – HiLink: klient DHCP na `lte1` z trasą domyślną o odległości 10; tryb `Modem`: profil APN + PIN.
   Jeśli RouterOS 7 sam założył na `lte1` dynamiczny klient DHCP (tak robi z wieloma stickami HiLink i wtedy
   nie pozwala dodać drugiego), trasę (odległość 10) i DNS ustawiamy w profilu APN modemu; gdy RouterOS przyjmie
   je dopiero po ponownym połączeniu modemu, wynik zawiera ostrzeżenie (wyjąć i włożyć modem albo zrestartować router).
7. **Failover** – trasy rekurencyjne przez hosty kontrolne (patrz niżej) + netwatch czyszczący połączenia NAT przy przełączeniu.
8. **WAN** – ether1 jako **klient DHCP** (usuwa statyczne adresy), czeka na dzierżawę i zwraca adres od operatora.
9. **NAT** – maskarada na liście `WAN`.
10. **Firewall** – własne reguły IPv4/IPv6 na górze tabeli (wejście tylko z LAN i VPN, forward LAN→WAN, VPN↔LAN),
    usuwa reguły fabryczne `defconf`.
11. **Usługi** – wyłącza telnet, ftp, www, www-ssl, api-ssl; discovery/MAC-Winbox tylko na LAN; wyłącza bandwidth-server.
12. **VPN** – interfejs WireGuard, adres tunelu, peer huba (keepalive 25 s), trasy, watchdog.
13. **DHCP LAN** – pula, sieć DHCP, serwer, stałe dzierżawy urządzeń, nazwa `router.lan`.
14. **Hasło** – nowe hasło użytkownika, na którym jesteśmy zalogowani; **sprawdzane drugim logowaniem**
    (gdy nie zadziała, przywracane jest stare).
15. **Adres LAN** – zawsze **ostatni**, jedną komendą (zmienia adres, przez który laptop widzi router).

Ponowne wysłanie tego samego pakietu **niczego nie zmienia** (każdy obiekt jest odszukiwany po nazwie
lub komentarzu `itbees:...` i zmieniane są tylko różnice), więc pakiet można wysyłać z panelu admina w dowolnym momencie.

## Failover: łącze podstawowe → LTE → z powrotem

Samo „kabel odpięty” wykrywa każdy router; na parkingu częstszy jest przypadek, gdy kabel jest wpięty, ale za
routerem klienta nie ma internetu. Dlatego biblioteka używa **tras rekurencyjnych** (standardowa metoda MikroTika):

```
/ip route add dst-address=1.0.0.1/32        gateway=<brama z DHCP na ether1> scope=10
/ip route add dst-address=0.0.0.0/0         gateway=1.0.0.1 distance=1 check-gateway=ping target-scope=11
/ip route add dst-address=208.67.222.222/32 gateway=<brama z DHCP na ether1> scope=10
/ip route add dst-address=0.0.0.0/0         gateway=208.67.222.222 distance=2 check-gateway=ping target-scope=11
LTE (klient DHCP na lte1):                  trasa domyślna distance=10
```

- RouterOS co 10 s pinguje hosty kontrolne **zawsze przez ether1**. Jeśli żaden nie odpowiada (≈20–30 s),
  trasy distance 1–2 gasną i ruch idzie przez LTE. Gdy internet za ether1 wraca, trasy się zapalają i ruch
  **sam wraca** na łącze podstawowe.
- Klient DHCP na ether1 nie dodaje własnej trasy domyślnej; skrypt dzierżawy przestawia trasy kontrolne na
  aktualną bramę, gdy sieć klienta da inną.
- Przy każdym przełączeniu netwatch czyści tablicę połączeń, żeby sesje NAT (np. szlaban ↔ serwer) od razu
  zestawiły się przez nowe łącze, zamiast wisieć na starym adresie.
- **Hosty kontrolne nie mogą być serwerami DNS** (ruch do nich zawsze idzie przez ether1, więc DNS przestałby
  działać na LTE) — walidator tego pilnuje. Domyślnie: kontrola 1.0.0.1 i 208.67.222.222, DNS 1.1.1.1 i 8.8.8.8.
- LTE nie jest dodatkowo pingowane (nie ma dokąd przełączyć dalej), więc w normalnej pracy nie zużywa pakietu danych
  poza ruchem, który faktycznie przez nie idzie.

## VPN: stały tunel do naszego serwera

Każdy router zestawia tunel **WireGuard** do centralnego huba. Router zawsze sam inicjuje połączenie, więc działa
za NAT-em klienta i za CGNAT-em operatora LTE — nie potrzeba publicznego IP ani przekierowań portów.

Co zapewnia „tunel zawsze dostępny”:
- `persistent-keepalive=25s` – utrzymuje mapowania NAT po stronie klienta i operatora LTE;
- po przełączeniu łącza WireGuard sam przechodzi na nowy adres źródłowy (roaming), hub uczy się nowego endpointu;
- **watchdog** (skrypt co minutę): gdy ostatni handshake jest starszy niż 3 min, ponownie ustawia `endpoint-address`,
  co wymusza nowy handshake i ponowne rozwiązanie nazwy DNS huba (celowo nie disable/enable peera — w RouterOS 7.24
  zgłoszono błąd, przez który ponownie włączony peer nie wraca do pracy);
- port WireGuard jest otwarty na wejściu, więc hub może zainicjować połączenie po zmianie łącza;
- z VPN dostępne są: router (Winbox/API/SSH/ping) i urządzenia w LAN parkingu (gdy `AllowAccessToLan`).

Klucz prywatny routera: domyślnie generuje go router (nigdy go nie opuszcza), a biblioteka zwraca klucz publiczny
i gotową sekcję `[Peer]` dla huba (`result.VpnHubPeer`). Można też wygenerować parę kluczy wcześniej w backendzie
(`WireGuardKeys.GenerateKeyPair()`), żeby dodać peera na hubie przed montażem.

### Plan adresacji (zalecany)

| Zakres | Przeznaczenie |
|---|---|
| `10.250.0.0/16` | sieć VPN: hub `10.250.0.1`, parkingi `10.250.x.y` (unikalny adres na router) |
| `10.64.N.0/24` | LAN parkingu nr N (unikalny dla każdego parkingu, żeby z VPN dało się dojść do urządzeń) |
| unikać | `192.168.88.0/24` (fabryczny MikroTik), `192.168.8.0/24` (HiLink E3372), zakresy sieci klientów |

### Hub VPN (Linux, wg-quick)

```bash
apt install wireguard
wg genkey | tee /etc/wireguard/hub.key | wg pubkey > /etc/wireguard/hub.pub   # hub.pub -> Vpn.ServerPublicKey
sysctl -w net.ipv4.ip_forward=1    # i na stałe w /etc/sysctl.conf
```

`/etc/wireguard/wg0.conf` (można wygenerować `WireGuardHubConfig.BuildWgQuickConfig(...)`):

```ini
[Interface]
Address = 10.250.0.1/16
ListenPort = 51820
PrivateKey = <zawartość hub.key>

[Peer]
# octopark-krakow-p12          <- result.VpnHubPeer.ToWgQuickSection()
PublicKey = <klucz publiczny routera>
AllowedIPs = 10.250.0.12/32, 10.64.12.0/24
```

`systemctl enable --now wg-quick@wg0`, otworzyć UDP 51820. Nowego peera na działającym hubie dodaje
`result.VpnHubPeer.ToWgSetCommand()` (`wg set wg0 peer ... allowed-ips ...`). Hub może też być MikroTikiem (CHR) —
`ToRouterOsCommand()`.

## Wspólna sieć obiektu (jeden kabel, bez izolacji)

Gdy sieć obiektu nie pozwala przepiąć urządzeń parkingu „za” router (wszystko wisi na switchach klienta, a router
dostaje jeden kabel), pakiet ustawia się w tryb `Lan.Mode = SharedSiteNetwork`:

```
internet ── router klienta (DHCP 192.168.1.x) ──┬── switche obiektu ──┬── urządzenia klienta (DHCP klienta)
                                               │                     └── słupki, kamery, terminale parkingu:
                                       ether1 MikroTika                  stałe adresy 192.168.23.x,
                                       (DHCP 192.168.1.57 + 192.168.23.1/24)  brama 192.168.23.1
                                               │
                                       LTE (USB) = zapas, WireGuard do huba
```

Na jednym kablu działają dwie podsieci: sieć klienta (jego DHCP, przez nią router wychodzi do internetu) i podsieć
parkingu (`Lan.Address`). Urządzenia parkingu mają **stałe adresy** z podsieci parkingu i router jako bramę, więc ich
ruch idzie przez router: do internetu przez router klienta, a gdy ten internet padnie — przez LTE. Urządzenia klienta
niczego nie zauważą.

Co pakiet robi inaczej niż w trybie `OwnPorts`:
- adres LAN routera trafia na **ether1** (obok adresu z DHCP klienta); mostek ether2–ether5 + sfp1 zostaje bez
  adresu IPv4 jako porty serwisowe (dostępne przez IPv6 link-local),
- **żadnego serwera DHCP** (`Lan.Dhcp.Enabled` musi być `false`, walidator to sprawdza) — odpowiadałby urządzeniom
  klienta; `Lan.Dhcp.StaticLeases` są ignorowane (adresy ustawia się na urządzeniach),
- firewall wpuszcza z ether1 (do routera, do internetu/LTE i do VPN) **tylko podsieć parkingu**; reszta sieci klienta
  zostaje na zewnątrz,
- ruch z VPN do urządzeń wychodzi przez ether1, więc maskarada podstawia adres routera — urządzenia odpowiadają
  w swojej podsieci nawet ze źle ustawioną bramą,
- `/ip settings send-redirects=no`: ruch wchodzi i wychodzi tym samym portem, a przekierowania ICMP kazałyby
  urządzeniom (Linux je przyjmuje) iść prosto do routera klienta — z pominięciem failoveru i VPN,
- sesja przez ether1 nie jest odrzucana w preflight (w tym trybie słupek wdrażający pakiet siedzi w sieci obiektu).

Ograniczenia: urządzenie, które umie tylko DHCP, dostanie bramę od routera klienta i będzie działać bez zapasowego LTE
i bez dostępu przez VPN. Izolacji nie ma — z sieci klienta da się dojść do urządzeń parkingu (jeśli ktoś doda trasę).
Podsieć parkingu nie może pokrywać się z siecią klienta (preflight to sprawdza).

**Pierwsze wdrożenie fabrycznego routera:** fabrycznie RouterOS wpuszcza logowanie i discovery tylko od strony
ether2–ether5, a jego serwer DHCP (192.168.88.x) **nie może trafić do sieci klienta**. Dlatego na czas pierwszego
wdrożenia: ether1 do sieci obiektu, komputer/słupek wdrażający kablem **bezpośrednio do ether2** (nie przez switch
obiektu). Po wdrożeniu mostek traci adres 192.168.88.1 (sesja się kończy — `ReconnectRequired`), a słupek wraca do
sieci obiektu i od tej pory łączy się z routerem adresem z podsieci parkingu na ether1.

## Discovery „jak Winbox” i połączenie bez wspólnej podsieci

`DiscoverAsync()` wysyła zapytanie **MNDP** (UDP 5678) na broadcast i multicast IPv6 `ff02::1` na każdej karcie
sieciowej i nasłuchuje odpowiedzi oraz okresowych ogłoszeń routerów. To działa w warstwie 2, więc router zostanie
znaleziony nawet wtedy, gdy laptop ma np. statyczne `10.0.0.5`, a router `192.168.88.1`.

Do połączenia biblioteka próbuje kolejno (`MikrotikNeighbor.GetConnectionCandidates()`):
1. adresu IPv4, jeśli jest w podsieci laptopa,
2. adresu **IPv6 link-local** routera (z MNDP albo wyliczonego z MAC, EUI-64) — działa niezależnie od adresacji IPv4,
   bo RouterOS 7 ma IPv6 włączone fabrycznie (to zastępuje połączenie „po MAC” z Winboxa),
3. pozostałych adresów.

Fabrycznie RouterOS odpowiada na MNDP i wpuszcza logowanie **tylko od strony LAN**, dlatego laptop instalatora
podłączamy do portu **ether2–ether5**, a nie do sieci klienta na ether1.

## Przykład: nowy router na parkingu

```csharp
using ITBees.Mikrotik;
using ITBees.Mikrotik.Configuration;
using ITBees.Mikrotik.Discovery;

var mikrotik = new MikrotikService(loggerFactory);   // albo services.AddMikrotik() + IMikrotikService

var package = new MikrotikConfigurationPackage
{
    Identity = "octopark-krakow-p12",
    Security = { AdminPassword = parkingPassword },  // zapisane w panelu admina Octopark albo wspólne dla parkingów
    Lan =
    {
        Address = "10.64.12.1/24",
        Dhcp = { StaticLeases = { new StaticLease { MacAddress = "00:11:22:33:44:55", Address = "10.64.12.20", Comment = "szlaban wjazd" } } },
    },
    Vpn =
    {
        Enabled = true,
        Address = "10.250.0.12/16",
        ServerPublicKey = hubPublicKey,
        ServerEndpoint = "vpn.octopark.pl",
    },
};

var setup = await mikrotik.SetupAsync(new MikrotikSetupRequest
{
    Credentials = { new MikrotikCredentials("admin", stickerPassword) },  // hasło z naklejki
    Package = package,
});

var result = setup.Provisioning;
Console.WriteLine(result.WanAddress);                    // adres od operatora/klienta na ether1, np. 192.168.1.57/24
Console.WriteLine(result.VpnHubPeer!.ToWgQuickSection()); // do dodania na hubie VPN
foreach (var step in result.Steps) Console.WriteLine(step);
```

`SetupAsync` sam dokłada do listy haseł nowe hasło z pakietu, więc ponowne uruchomienie (np. po dołożeniu modemu)
też zadziała. Krok po kroku:

```csharp
var routers = await mikrotik.DiscoverAsync();                                   // lista MikroTików w sieci
var scan = await mikrotik.FindAndLoginAsync(new MikrotikLoginScanOptions
{
    Credentials = { new MikrotikCredentials("admin", stickerPassword) },
});                                                                             // MikrotikDeviceNotFoundException + Attempts
await using var client = scan.Client;

var plan = await mikrotik.ApplyConfigurationAsync(client, package, new() { DryRun = true });   // tylko podgląd zmian
var result = await mikrotik.ApplyConfigurationAsync(client, package);
var status = await mikrotik.GetStatusAsync(client, package);
// status.ActiveUplink: Primary / Backup (LTE) / None, status.Wan.Address, status.Lte.Rsrp, status.Vpn.IsConnected
```

Zarządzanie zdalne (już skonfigurowany router) — przez tunel, adresem VPN:

```csharp
await using var client = await mikrotik.ConnectAsync(new MikrotikConnectionOptions { Host = "10.250.0.12", Password = parkingPassword });
```

## Pakiet konfiguracyjny (JSON)

`MikrotikConfigurationPackage` serializuje się do JSON (`ToJson()` / `FromJson()`), więc może być przechowywany
w panelu admina i wysyłany do biblioteki bez zmian w kodzie. Pełny przykład: `mikrotik sample-package`.
Walidacja bez kontaktu z routerem: `package.Validate()` (błędy + ostrzeżenia), m.in.:
nowe hasło ≥ 8 znaków, WAN nie może być portem LAN, LAN nie może nachodzić na sieć VPN ani HiLink (192.168.8.0/24),
hosty kontrolne ≠ serwery DNS, pula DHCP w podsieci i bez adresu routera, poprawne klucze WireGuard.
W trakcie konfiguracji dodatkowo: **LAN nie może nachodzić na sieć klienta na ether1** (np. klient też ma 192.168.88.x).

Najważniejsze pola i wartości domyślne:

| Sekcja | Pole | Domyślnie |
|---|---|---|
| `security` | `adminPassword` | wymagane (albo `keepCurrentPassword: true`) |
| | `disabledServices` | telnet, ftp, www, www-ssl, api-ssl |
| `wan` | `interface`, `usePeerDns`, `waitForLeaseSeconds` | ether1, false, 20 |
| `lte` | `enabled`, `interface`, `mode` (`HiLink`/`Modem`), `apn`, `pin`, `routeDistance` | true, lte1, HiLink, –, –, 10 |
| `failover` | `enabled`, `checkHosts`, `flushConnectionsOnSwitch` | true, [1.0.0.1, 208.67.222.222], true |
| `lan` | `ports`, `address`, `dhcp.poolStart/poolEnd`, `dhcp.staticLeases` | ether2–5 + sfp1, 192.168.88.1/24, .100–.250 |
| `dns` | `servers` | 1.1.1.1, 8.8.8.8 |
| `vpn` | `enabled`, `address`, `serverPublicKey`, `serverEndpoint`, `serverPort`, `privateKey`, `allowedAddresses` | false, –, –, –, 51820, generowany na routerze, sieć VPN |

## Bezpieczeństwo zmian

- **Kolejność kroków** jest dobrana tak, żeby sesja nie została zerwana w połowie: reguły firewalla są
  przesuwane na górę po jednej, od góry, więc w każdej chwili reguły „accept” są nad „drop” (sprawdza to test);
  trasy failover powstają, zanim klient DHCP przestanie dodawać swoją trasę domyślną (router nie traci trasy);
  nowy adres LAN jest ustawiany na samym końcu, jedną komendą.
- Jeśli sesja szła przez stary adres LAN, po ostatnim kroku zrywa się (to oczekiwane): `result.ReconnectRequired`
  i `result.LanRouterAddress` mówią, gdzie router jest teraz (laptop musi odnowić dzierżawę DHCP).
- Konfiguracja przez WAN (sieć klienta) albo LTE jest odrzucana — zarządzany firewall zamyka te interfejsy.
  Łącz się z portu LAN albo przez VPN (`AllowManagementOverWan` tylko w wyjątkowych przypadkach).
- Wyłączenie VPN pakietem jest odrzucane, jeśli sesja idzie właśnie przez ten VPN.
- API RouterOS nie ma limitu prób logowania — dlatego firewall wpuszcza API wyłącznie z LAN i VPN.
- Hasła i klucze są maskowane w logach i w liście zmian (`password=***`).

Ograniczenia, o których warto wiedzieć: firewall nie używa fasttracka (prostsze i przewidywalne przy failoverze,
w zupełności wystarcza dla ruchu parkingowego); ręcznie dodane reguły trzeba umieszczać nad regułami `itbees:`;
statyczne trasy domyślne spoza biblioteki są usuwane (omijałyby failover).

## Narzędzie dla instalatora (CLI)

```bash
dotnet run --project ITBees.Mikrotik.Cli -- discover
dotnet run --project ITBees.Mikrotik.Cli -- find --password <hasło z naklejki>
dotnet run --project ITBees.Mikrotik.Cli -- apply --package parking-p12.json --password <hasło z naklejki> --dry-run
dotnet run --project ITBees.Mikrotik.Cli -- apply --package parking-p12.json --password <hasło z naklejki>
dotnet run --project ITBees.Mikrotik.Cli -- status --host 10.250.0.12 --password <hasło parkingu>
dotnet run --project ITBees.Mikrotik.Cli -- sample-package
dotnet run --project ITBees.Mikrotik.Cli -- wg-keys
```

## Do sprawdzenia na pierwszym prawdziwym urządzeniu

Biblioteka jest przetestowana na emulatorze API RouterOS (stan fabryczny RB960PGS: pełna konfiguracja, ponowne
zastosowanie bez zmian, dry run, kolejność reguł, ciągłość trasy domyślnej, logowanie MD5/nowe, `!empty` z 7.18).
Na sprzęcie trzeba potwierdzić:

1. **Logowanie hasłem z naklejki przez API** na nowym routerze. Jeśli RouterOS wymusza zmianę hasła przy
   pierwszym logowaniu, biblioteka zgłosi `MikrotikPasswordExpiredException` — wtedy hasło trzeba raz zmienić
   w Winboxie (albo ustalimy obejście na konkretnej wersji RouterOS).
2. **Tryb modemu E3372**: firmware 22.x = HiLink (`lte1` + DHCP 192.168.8.x, APN/PIN w panelu http://192.168.8.1),
   21.x = tryb „stick” (wtedy `lte.mode = Modem` + `apn`). Sprawdzić, że `/interface print` pokazuje `lte1`.
3. **Failover**: odłączyć internet *za* routerem klienta (nie kabel ether1) → po ok. 20–30 s `status.ActiveUplink`
   = `Backup`; przywrócić → wraca `Primary`. To samo z odłączeniem kabla ether1.
4. **VPN po przełączeniu łącza**: handshake wraca w ciągu ~1 min (`status.Vpn.IsConnected`).
5. **Połączenie przez IPv6 link-local**: laptop ze statycznym IPv4 z innej podsieci → `discover` pokazuje router,
   `find` loguje się adresem `fe80::...%<karta>`.
6. **Wspólna sieć obiektu** (`SharedSiteNetwork`): urządzenie ze stałym adresem z podsieci parkingu wychodzi do
   internetu przez router (traceroute: pierwszy skok = adres LAN routera), po odcięciu internetu klienta przechodzi
   na LTE, a słupek Chipsee nie zmienia bramy po ruchu przez router (brak przekierowań ICMP).

Nie zaimplementowano protokołu MAC-Telnet (logowanie po samym MAC jak w Winboxie): na RouterOS 7 tę rolę pełni
IPv6 link-local. Jeśli trafią się routery z RouterOS 6 (bez IPv6), MAC-Telnet można dodać jako osobny transport.

## Testy

```bash
dotnet test
```
