# outstation — bruksanvisning for SCADA-ingeniører

*Hvordan kjøre realistisk replay av IEC 60870-5-104-trafikk mot en SCADA-server i et virtuelt testlab, uten å røre SCADA-en.*

---

## Innhold

1. [Kort om verktøyet](#1-kort-om-verktøyet)
2. [Hva det gjør i praksis](#2-hva-det-gjør-i-praksis)
3. [Nettverksutfordringen — hvorfor replay er vanskelig](#3-nettverksutfordringen)
4. [Anbefalt oppsett i VMware / Proxmox / virtuelt miljø](#4-anbefalt-oppsett)
5. [Steg for steg: sette opp labben](#5-steg-for-steg)
6. [Steg for steg: kjøre en replay](#6-kjøre-en-replay)
7. [Forstå resultatene](#7-forstå-resultatene)
8. [Feilsøking](#8-feilsøking)
9. [Begreper og kortliste](#9-begreper)

---

## 1. Kort om verktøyet

**outstation** er et verktøy for å spille av fanget nettverkstrafikk — typisk IEC 60870-5-104 fra reelle RTU-er — mot et testmål, på en slik måte at du kan:

- **Benchmarke** en SCADA-server ved å slippe løs et realistisk antall RTU-sesjoner mot den samtidig, og måle latens, gjennomstrømning og om noen meldinger mistes.
- **Regresjonsteste** en SCADA-oppgradering ved å spille av den samme trafikken før og etter, og sammenligne responsen.
- **Simulere last** — for eksempel 200 RTU-er som sender 50 meldinger i sekundet hver — fra én enkelt Linux-VM.
- **Fôre IDS-/logger-/historian-systemer** med realistisk trafikk uten å måtte ha de ekte RTU-ene tilkoblet.

Verktøyet er styrt fullt ut fra et nettgrensesnitt i nettleseren (`http://<replay-vm>:8080`). Det er ingen kommandolinje-arbeidsflyt — du laster opp pcap-filer, konfigurerer en kjøring, trykker start, og ser på resultatene i samme grensesnitt.

### To kjøremoduser

| Modus | Hva skjer | Bruksområde |
|---|---|---|
| **Raw replay** | Pakkene fra pcap-filen blir skrevet rått ut på nettverket via AF_PACKET, med opprinnelsesadresser uendret, men med destinasjonen omskrevet til ditt mål. Ingen TCP-tilstand, ingen ack. | Fôre IDS-er, wire-tap-analyse, logger-regresjon. |
| **Benchmark / stateful session replay** | Verktøyet åpner en reell TCP-sesjon per RTU i pcap-en, kjører en protokoll-bevisst replay (IEC 104), venter på ack-er, måler latens. | Lasttesting av SCADA-server, session-regresjon, respons-måling. |

Denne veiledningen fokuserer på benchmark-modus mot en SCADA-server, siden det er her SCADA-ingeniøren typisk har bruk for verktøyet.

---

## 2. Hva det gjør i praksis

La oss si du har en pcap fanget fra produksjon, med trafikk fra 200 RTU-er som alle kommuniserer med en SCADA-master over IEC 60870-5-104. Pcap-en er på 3 GB og dekker en time.

Du peker outstation på et SCADA-testsystem, velger "benchmark"-modus og trykker start. Det som skjer:

1. **Pcap-analyse.** Verktøyet leser filen, identifiserer alle TCP-flows, grupperer pakkene per kilde-IP (per RTU), og plukker ut de meldingene som er relevante for IEC 104.
2. **Sesjonsoppsett.** For hver RTU i pcap-en opprettes et TCP-socket som binder seg til den RTU-ens originale kilde-IP (via automatiske IP-aliaser på lokalt nettgrensesnitt), og kobler seg til SCADA-testserveren på port 2404.
3. **IEC 104-handshake.** Hver sesjon sender `STARTDT act` og venter på `STARTDT con` fra SCADA. K-vinduet settes opp (standard `k=12`, `w=8`).
4. **Meldingsstrøm.** Hver sesjon spiller av sine I-rammer mot SCADA med ønsket pacing (maksimal hastighet eller original pcap-timing), venter på S-rammer / ack-er, måler latens send→ack for hver enkelt melding.
5. **Live rapportering.** I nettgrensesnittet ser du et live nettverksdiagram med animerte datapakker (ekte retning og hastighet), progress-barer per RTU, gjennomstrømning i pakker per sekund, og en latenstidshistogram som oppdateres underveis.
6. **Avslutning.** Når alle sesjoner er ferdige, lagres rapporten i en SQLite-database, pakkene som ble sendt på wire lagres som en egen pcap (kan lastes ned for verifisering), og du ser aggregerte statistikker: p50/p90/p99-latens, meldinger sendt/mottatt, feil, per-sesjon-detaljer.

---

## 3. Nettverksutfordringen

Dette er kanskje den viktigste delen å forstå.

### Problemet

Pcap-en inneholder trafikk fra 200 RTU-er som er spredt over mange forskjellige subnett — for eksempel `192.168.10.0/24`, `172.16.5.0/24`, `10.50.0.0/16`, osv. Disse IP-ene er de *ekte* adressene til RTU-ene i produksjon.

SCADA-testserveren har sannsynligvis en whitelist: den godtar bare tilkoblinger fra adresser den kjenner — som er de samme RTU-adressene fra produksjon.

Så langt, alt vel: outstation sender pakker med de ekte kilde-IP-ene, SCADA godtar dem fordi de matcher whitelisten, og TCP-SYN-en kommer fram.

**Men** — SCADA må svare tilbake på SYN-en. SCADA-ens kjerne slår opp i rutetabellen sin: *"Hvor skal jeg sende pakker til 192.168.10.42?"*. Hvis SCADA-en står på `10.0.0.0/24`, har den ingen direkte rute til `192.168.10.0/24`. Den sender svaret til sin default gateway. Default gateway har heller ingen rute dit. Svaret dør.

TCP-handshaken fullføres aldri. Ingen IEC 104-sesjon opprettes. Benchmarken feiler før den har startet.

### Hvorfor man ikke kan "bare konfigurere det på SCADA-en"

Den åpenbare løsningen — *"bare legg inn statiske ruter på SCADA som peker RTU-subnettene tilbake til outstation"* — er ikke alltid akseptabelt:

- SCADA-serveren kan være en produksjonslignende test som skal være "uten endring".
- Du har ikke root-tilgang på SCADA.
- Endringene må dokumenteres, godkjennes, og rulles tilbake — alt er overhead.
- Testen skal være **non-invasive**: SCADA-en skal oppføre seg nøyaktig som i produksjon.

Vi trenger en løsning der vi manipulerer **SCADAens nettverksmiljø**, ikke SCADA-en selv.

### Løsningen: isolert virtuell switch

Hvis både outstation og SCADA kjører som virtuelle maskiner — noe de gjør i dette oppsettet — kan vi sette dem begge på en **isolert virtuell switch** der outstation er den eneste naboen SCADA kan se på lag 2.

Da skjer følgende, helt automatisk:

1. SCADA prøver å sende en TCP SYN-ACK til `192.168.10.42`.
2. Rutetabellen sier: "off-subnet, send til default gateway `10.0.0.1`".
3. SCADA gjør en ARP: *"Hvem har `10.0.0.1`?"*.
4. På en isolert switch er outstation den eneste som hører ARP-spørsmålet. Pcapreplay har fått `10.0.0.1` lagt til som et lokalt /32-alias på sitt indre nettgrensesnitt, og svarer: *"Det er meg."*
5. SCADA sender SYN-ACK-en til outstation sin MAC-adresse.
6. Pcapreplay tar imot pakken på kjernenivå, og fordi `192.168.10.42` også er et lokalt alias, ruter kjernen pakken opp til brukerrommet, der benchmark-sesjonen bundet til `192.168.10.42:0` venter på den. Handshaken fullføres.

SCADA har **ikke blitt konfigurert om**. Den tror fortsatt den snakker med sin default gateway. Whitelisten stemmer fortsatt fordi vi ikke har rørt kilde-IP-en. Alt er som i produksjon — *bortsett fra* at det fysiske laget har blitt skjøvet til en isolert virtuell switch.

---

## 4. Anbefalt oppsett

### Topologi

```
┌─────────────────────┐        ┌──────────────────────────┐
│                     │        │                          │
│    SCADA (VM)       │        │     outstation (VM)      │
│                     │        │                          │
│   eth0              │        │  eth0 (indre)            │
│   10.0.0.50/24      ├────────┤  10.0.0.1/24   (*)       │
│   gw: 10.0.0.1      │        │  + 192.168.10.0/24 alias │
│                     │        │  + 172.16.5.0/24 alias   │
│                     │        │  + ...                   │
│                     │        │                          │
└─────────────────────┘        │  eth1 (ytre)             │
                               │  10.20.30.40/24          │
          isolert vSwitch     │  gw: 10.20.30.1          │
          "vswitch_test"      └───────────┬──────────────┘
                                          │
                                          │
                                  ekte lab-nettverk
                                  (internett, admin, NTP,
                                   oppdateringer for SCADA)
```

(*) `10.0.0.1` er et eksempel — det skal være den samme IP-en som SCADA allerede har konfigurert som sin default gateway. Vi bruker det SCADA *allerede tror* er gatewayen, vi skaper ingen ny konfigurasjon på SCADA-siden.

### Komponenter

- **SCADA-VM**: din eksisterende SCADA-testserver. Ingen endringer. Flyttes bare over på den nye isolerte switchen.
- **outstation-VM**: en ren Ubuntu / Debian / RHEL-installasjon med `outstation`-binæren, to vNIC-er.
- **Isolert virtuell switch** (kalt `vswitch_test` her): i VMware ESXi: "Port Group" uten uplink; i vSphere: "Private VLAN"; i Proxmox: en Linux Bridge uten fysisk interface; i VirtualBox: "Internal Network"; i libvirt/KVM: `<forward mode='none'/>`.

### Hvorfor to vNIC-er på outstation?

- **eth0 (indre)**: eneste kontakt med SCADA. Her legges alle RTU-aliaser og gateway-aliaset.
- **eth1 (ytre)**: outstation-VM-en selv trenger tilgang til det ekte lab-nettet for admin/SSH/oppdateringer. I tillegg brukes eth1 som NAT-utgang slik at SCADA fortsatt kan hente NTP, oppdateringer osv. via outstation. Dette er valgfritt — hvis SCADA skal være helt isolert under testen, kan du droppe eth1.

---

## 5. Steg for steg: sette opp labben

Dette gjør du én gang per testlab. Etterpå er det kun pcap-opplasting og knappetrykk i nettgrensesnittet.

### 5.1 Opprett den isolerte switchen

**VMware vSphere / ESXi:**

1. Gå til *Host → Networking → Virtual switches → Add standard virtual switch*.
2. Kall den `vswitch_test`.
3. **Ikke legg til noen physical uplink.** Denne switchen skal ikke være tilkoblet noen NIC.
4. Gå til *Port groups → Add port group*, navngi den `pg_scada_test`, velg `vswitch_test` som uplink.
5. VLAN-ID kan stå som 0.

**Proxmox VE:**

1. *Datacenter → Node → Network → Create → Linux Bridge*, navngi den `vmbr_test`.
2. La "Bridge ports" stå tom.
3. Ikke gi den en IP.

**libvirt / virt-manager:**

```xml
<network>
  <name>isolated-test</name>
  <forward mode='none'/>
  <bridge name='virbr-test' stp='on'/>
</network>
```

Last inn med `sudo virsh net-define isolated.xml && sudo virsh net-start isolated-test && sudo virsh net-autostart isolated-test`.

### 5.2 Flytt SCADA-VM over på den nye switchen

1. Slå av SCADA-VM-en, eller — om den støtter det — hot-swap vNIC-en.
2. I VM-innstillingene: endre network adapter fra dagens switch til `pg_scada_test` / `vmbr_test` / `isolated-test`.
3. Ikke endre noe inne i SCADA-gjesten. IP-adresse, netmask, default gateway, DNS — alt skal være uendret.
4. Start SCADA-en igjen.

Viktig: etter flyttingen vil SCADA-en miste all nettverkskontakt inntil outstation-VM-en også er koblet til den samme isolerte switchen. Dette er forventet.

### 5.3 Opprett outstation-VM-en

1. Opprett en ny VM med 4 vCPU, 8 GB RAM (for 200 RTU-er), 40 GB disk.
2. Installer Ubuntu Server 22.04 LTS eller lignende.
3. Legg til **to** vNIC-er:
   - `eth0` → **`vswitch_test` / `pg_scada_test`** (indre — mot SCADA).
   - `eth1` → din vanlige lab-switch (ytre — mot det ekte nettet).
4. Sett en statisk IP på `eth0`. Bruk **samme IP som SCADA-en har som default gateway** — for eksempel `10.0.0.1/24`. Ikke sett gateway på denne.
5. Sett en IP på `eth1` som passer det ekte lab-nettet, og sett default gateway på den.
6. Installer outstation og systemd-tjenesten (følg `systemd/install.sh` i repoet).

Du kan verifisere ved å pinge SCADA fra outstation: `ping 10.0.0.50`. Hvis det svarer, er det fysiske laget i orden.

### 5.4 Åpne nettgrensesnittet

Fra arbeidsstasjonen din, åpne `http://<outstation-eth1-ip>:8080` i nettleser. Du skal se oversikten med seksjoner for "Pcap Library", "Run Configuration", "Runs" og "Network Diagram".

---

## 6. Kjøre en replay

### 6.1 Last opp pcap-filen

1. Gå til **Pcap Library**-seksjonen.
2. Dra-og-slipp pcap-en eller pcapng-en din inn i opplastingsfeltet.
3. Vent til analysen er ferdig — du ser antall pakker, RTU-er, TCP-flows, lengde og en "viability"-vurdering av om pcap-en egner seg for benchmark-modus.

### 6.2 Konfigurer kjøringen

I **Run Configuration**-seksjonen:

1. **Velg pcap**: klikk på pcap-en du nettopp lastet opp.
2. **Target IP**: SCADA-testserverens IP, f.eks. `10.0.0.50`.
3. **Target port**: `2404` for IEC 104 (standard).
4. **Egress NIC**: velg `eth0` (indre, mot SCADA). Dette er nettgrensesnittet der AF_PACKET-injeksjonen og TCP-sesjonene skal sendes ut.
5. **Flags** → haken på **"benchmark mode"**.
6. **Role**: "target is server · tool connects out as master" (dette er standard).
7. **Protocol**: `iec104`.
8. **Pacing**: velg "as fast as possible" for maksbelastning, eller "original pcap timing" for realisme.
9. **Iterations**: antall ganger scriptet skal løpe. `1` for et enkelt pass, `0` for uendelig løkke.

### 6.3 Aktiver SCADA-gateway-modus

Dette er det nye, kritiske trinnet. Haken du har ventet på:

1. Huk av **"act as scada gateway"** nederst i benchmark-panelet.
2. **SCADA-side gateway IP**: den IP-en SCADA har som default gateway — i vårt eksempel `10.0.0.1`. Dette er IP-en outstation vil hekte på som /32-alias under kjøringen.
3. **Inner NIC**: velg `eth0` (samme som egress NIC — det er den som peker mot SCADA).
4. **Upstream NAT NIC** *(valgfritt)*: velg `eth1` hvis SCADA skal ha fortsatt tilgang til det ekte nettet (oppdateringer, NTP, admin) mens testen kjører. outstation vil da slå på IP-forwarding og legge til en MASQUERADE-regel for `eth1`. La være tom hvis SCADA skal være helt isolert under testen.

### 6.4 Start

Trykk **START RUN**. Det som skjer bak kulissene:

1. outstation installerer `10.0.0.1/32` som alias på `eth0`.
2. IP-forwarding slås på (hvis NAT er valgt).
3. MASQUERADE-regelen settes inn i `iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE`.
4. For hver RTU i pcap-en legges RTU-IP-en til som /32-alias på `eth0` via bestående auto-alias-mekanismen.
5. pcr_br0-broen opprettes, veth-interfaces per kilde etableres.
6. Sesjonene kobler seg til SCADA-en én etter én (eller samtidig, avhengig av concurrency-valg).
7. SCADA svarer på ARP-spørsmål for `10.0.0.1` (via oss) og `192.168.10.42` (via oss direkte på lag 2 — selv om det ikke er nødvendig siden det går via default gateway).
8. Sesjonene strømmer I-rammer, måler latens, logger til SQLite.

Nettgrensesnittet viser live nettverksdiagram med animerte datastrømmer, progress-bar per RTU, og latens-sparkline.

### 6.5 Når kjøringen er ferdig

outstation rydder opp alt automatisk:

- /32-aliaset på `eth0` fjernes.
- IP-forwarding tilbakestilles til opprinnelig verdi.
- MASQUERADE-regelen slettes.
- Veth-interfacene og pcr_br0-broen rives.
- Alle endringer er reversible.

Hvis outstation-prosessen krasjer midt i en kjøring, blir aliasene og MASQUERADE-regelen liggende. Ved oppstart ser outstation etter dette i statusfilen `/var/lib/outstation/state-aliases.txt` og fjerner spor etter forrige kjøring automatisk. Du får en advarsel i loggen: *"reclaimed N orphaned ip alias(es) from a previous run"*.

---

## 7. Forstå resultatene

Når kjøringen er ferdig ser du en "Run card" i **RUNS**-seksjonen. Klikk **DETAILS** for å utvide.

### Aggregerte tall

- **Total messages sent / received**: skal matche antall I-rammer i pcap-en (sendt) og det SCADA-en responderte med (mottatt).
- **Aggregate latency p50/p90/p99/max**: send→ack-tid målt per melding, aggregert over alle RTU-er. Dette er den viktigste tallet for SCADA-benchmarking.
- **Aggregate throughput (msgs/sec)**: summen av alle sesjoners meldinger per sekund.

### Per-sesjon-detaljer

En rad per RTU, med:

- **connected**: om TCP-handshaken faktisk kom gjennom (dette er din første sanitetssjekk).
- **messages sent / received / bytes**
- **latency p50/p90/p99/max**: per-sesjons latens.
- **window stalls**: antall ganger sesjonen måtte vente på et `w`-ack fra SCADA fordi k-vinduet var fullt. Høyt tall her = SCADA henger etter på ack-sendingen.
- **unacked at end**: meldinger som ble sendt men ikke fikk ack før sesjonen stengte. Bør være 0.
- **error**: hvis sesjonen feilet, står feilmeldingen her.

### Fanget pcap

outstation lagrer alt som faktisk ble sendt på wire under kjøringen til `/tmp/outstation-captures/run_<id>.pcap`. Du kan laste denne ned via **DOWNLOAD CAPTURE**-knappen og åpne den i Wireshark for å verifisere at det som gikk ut matcher forventningen.

### Timing-sammenligning

Under **DETAILS** kan du også se en histogramsammenligning av inter-frame-gaps i original pcap vs det som faktisk ble sendt. Dette lar deg vurdere hvor nøyaktig pacing-en var. Typisk forskjell: millisekund-nivå på p99-halen, noe som er normalt for userspace-scheduling på Linux.

### SQLite-persistens

Alle kjøringer lagres i `/var/lib/outstation/runs.sqlite`. Etter en server-restart ligger alle historiske kjøringer der fortsatt, med rapporter og alt, og du kan slette dem individuelt via **DELETE**-knappen på hver run card.

---

## 8. Feilsøking

### SCADA får ikke kontakt med outstation

Sjekk fra outstation-VM-en:

```sh
ping 10.0.0.50                       # SCADA-ens IP
ip addr show eth0                    # skal vise 10.0.0.1/24
ip neigh | grep 10.0.0.50            # skal vise SCADA-ens MAC
```

Hvis pingen feiler, sjekk at begge VM-ene faktisk står på samme isolerte switch i hypervisoren.

### TCP-sesjonen etableres ikke

I nettgrensesnittets per-sesjon-rad er `connected` fortsatt `false` etter 10 sekunder.

- **Verifiser at gateway-aliaset er installert**: `ip addr show eth0 | grep "10.0.0.1"`. Skal være der under kjøringen.
- **Verifiser at RTU-IP-aliaset er installert**: `ip addr show eth0 | grep "192.168.10.42"` (eller hvilken RTU du tester).
- **Sjekk at SCADA-en faktisk har `10.0.0.1` som default gateway**: `ip route` på SCADA — selv om vi ikke skal endre noe på SCADA, kan du fritt lese konfigurasjonen.
- **Sjekk at kilde-IP-en matcher SCADA-ens whitelist**. Dette er den vanligste feilen: du bruker en pcap fra et annet miljø, og SCADA-testserveren godtar ikke de kilde-IP-ene.

### "TCP RST" fra outstations egen kjerne

Hvis du i Wireshark (på outstation-siden) ser at outstation-kjernen svarer med RST på SYN-ACK-er fra SCADA, betyr det at RTU-IP-en ikke er lagt til som lokalt alias, og kjernen vet ikke at det er en "lokal" adresse. Dette skjer kun hvis den pre-emptive auto-alias-mekanismen har sviktet. Sjekk `/var/log/syslog` for feil fra `netctl::add_ip_alias`.

### SCADA mister all internett-tilgang

Du glemte å huke på "upstream NAT NIC". SCADA-en står isolert med kun outstation som nabo, og kommer seg ikke videre. Enten aktiver NAT-modus i neste kjøring, eller aksepter at SCADA er isolert under testen (ofte det beste uansett).

### Kjøringen henger på warmup

Benchmark-modus har et valgfritt warmup-intervall (standard 0 sekunder). Hvis du har satt en høy verdi, er det forventet at sesjonene ikke begynner å sende før warmup er ferdig. Warmup-tiden brukes for å la deg attache Wireshark / tcpdump på `eth0` før trafikken starter.

### Pcapreplay krasjer og lar aliasene stå igjen

Start outstation på nytt: `sudo systemctl restart outstation` (eller manuell start av binæren). Den rydder opp automatisk ved oppstart og logger `reclaimed N orphaned ip alias(es)`.

Hvis du vil rydde manuelt:

```sh
sudo cat /var/lib/outstation/state-aliases.txt
sudo ip addr del 10.0.0.1/32 dev eth0
sudo iptables -t nat -D POSTROUTING -o eth1 -j MASQUERADE
sudo sysctl net.ipv4.ip_forward=0
```

---

## 9. Begreper

| Begrep | Forklaring |
|---|---|
| **IEC 60870-5-104** | Standard for SCADA-kommunikasjon, TCP-basert, port 2404. Sender I-, S- og U-rammer; bruker et glidende k-vindu for flytkontroll. |
| **I-frame** | "Information frame" — den faktiske nyttelasten med ASDU-data (målinger, kommandoer, hendelser). |
| **S-frame** | "Supervisory frame" — ack-ramme som bekrefter mottak av N I-rammer. |
| **U-frame** | "Unnumbered frame" — styrings-rammer (STARTDT, STOPDT, TESTFR). |
| **k-vindu** | Maksimalt antall u-bekreftede I-rammer en sender kan ha ute. Standard k=12. |
| **w-vindu** | Mottaker må sende S-frame ack senest etter w mottatte I-rammer. Standard w=8. |
| **ASDU** | "Application Service Data Unit" — innholdet i en I-frame: type-ID, COT (cause of transmission), common address, IOA (information object address), verdier. |
| **RTU** | "Remote Terminal Unit" — fjernstasjon som rapporterer til SCADA. I denne labben er hver RTU representert av én TCP-sesjon fra outstation. |
| **SCADA master** | Systemet som samler inn data fra RTU-er. Når vi kjører benchmark i "master"-rolle, er outstation klienten og SCADA er serveren. |
| **pcap / pcapng** | Pakkefangstformater. outstation støtter begge. |
| **AF_PACKET** | Linux-mekanisme for å sende/motta rå Ethernet-rammer direkte, uten å gå via TCP/IP-stakken. Brukt av outstation for raw replay-modus. |
| **MASQUERADE** | NAT-regel i iptables som rewriter kildeadressen til utgangs-NICens adresse. Brukt her for å gi SCADA upstream-tilgang. |
| **Isolert vSwitch** | Virtuell switch som ikke er tilkoblet noen fysisk NIC. Kun VM-er som er koblet til samme switch kan snakke med hverandre. |
| **/32-alias** | En IP-adresse lagt til på et nettgrensesnitt med subnet-maske 32, som betyr "bare denne enkle adressen, ingen subnet-rute". Brukt for å hekte gateway-IP-en og RTU-IP-ene på `eth0` uten å rote med rutetabellen. |

---

## Kontakt og ressurser

- Prosjektets README: [`README.md`](../README.md) i rotmappen.
- Protokollkode: `crates/proto_iec104/`.
- SCADA-gateway-implementasjon: `crates/netctl/src/lib.rs` (søk etter `GatewayGuard`).

God testing.
