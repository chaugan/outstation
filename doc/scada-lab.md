# outstation: veiledning for SCADA-ingeniører

*Slik tester du en SCADA-master, en RTU eller en frontend med avspilt IEC 60870-5-104-trafikk i et virtuelt lab, uten å endre noe i systemet som testes.*

Denne norske versjonen følger den engelske, [scada-lab.en.md](scada-lab.en.md), som er referansen.

---

## Innhold

1. [Hva verktøyet gjør](#1-hva-verktøyet-gjør)
2. [Velg scenario](#2-velg-scenario)
3. [Lab-topologi](#3-lab-topologi)
4. [Gateway-modus: når SCADA-masteren står på et annet subnett](#4-gateway-modus-når-scada-masteren-står-på-et-annet-subnett)
5. [Scenario A: test av en SCADA-master](#5-scenario-a-test-av-en-scada-master)
6. [Scenario B: test av en RTU eller en server](#6-scenario-b-test-av-en-rtu-eller-en-server)
7. [Oppsett av labben steg for steg](#7-oppsett-av-labben-steg-for-steg)
8. [Slik leser du resultatene](#8-slik-leser-du-resultatene)
9. [Repeterbare tester: profiler, ny kjøring, sammenligning, CI](#9-repeterbare-tester-profiler-ny-kjøring-sammenligning-ci)
10. [Opprydding og sikkerhet](#10-opprydding-og-sikkerhet)
11. [Feilsøking](#11-feilsøking)
12. [Ordliste](#12-ordliste)

---

## 1. Hva verktøyet gjør

**outstation** tar et opptak (pcap eller pcapng) av ekte IEC 60870-5-104-trafikk og spiller den ene siden av det live mot systemet du vil teste:

- **Det spiller RTU-ene** (slave-rolle): én lytter per RTU i opptaket, på RTU-ens egen IP og port 2404. SCADA-masteren din kobler seg til dem slik den gjør i produksjon. De avspilte RTU-ene sender den opptatte telemetrien, svarer på masterens generelle utspørringer og telleverdi-utspørringer (GI og CI), og bekrefter kommandoene den sender.
- **Det spiller masteren** (master-rolle): én klientsesjon per master i opptaket, som kobler seg til RTU-en, gatewayen eller frontenden du tester, og sender den opptatte mastertrafikken (utspørringer, kommandoer, klokkesynkronisering).

Under kjøringen måler verktøyet forsinkelsen per melding. Etterpå sammenligner det sitt eget opptak av kjøringen med kilde-pcap-en og gir hver RTU en dom (verdict) og en poengsum.

Bruk det til å:

- **lasttest** en SCADA-master med et realistisk antall RTU-sesjoner i opptakets tempo;
- **regresjonsteste** en oppgradering ved å kjøre samme opptak før og etter og sammenligne kjøringene;
- **sjekke hvordan en master håndterer utspørringer og kommandoer** mot avspilte RTU-er som svarer korrekt;
- **se hvordan motparten takler feil**: tilbakeholdte kvitteringer, tapte rammer, sekvensfeil, stillhet, tilbakestilte forbindelser;
- **mate IDS, loggere og historikere** med realistisk trafikk (rå avspilling).

Du kan styre det fra nettleser-UI-et (`http://<outstation-vert>:8080`), fra skript via [HTTP-API-et](api.md), eller uten UI med `outstation bench`, som passer i CI (se [avsnitt 9](#9-repeterbare-tester-profiler-ny-kjøring-sammenligning-ci)).

Det finnes to avspillingsmoduser:

| Modus | Hva som skjer | Bruk |
|---|---|---|
| **Tilstandsfull sesjon** (benchmark) | Ekte TCP-sesjoner som kjører IEC 104-linklaget: STARTDT, k/w-vinduer, kvitteringer, t1/t2/t3, TESTFR. Forsinkelsen måles. | Test av SCADA-mastere, RTU-er og frontender |
| **Rå L2-avspilling** | Hver opptatte ramme sendes slik den var, fra de opprinnelige avsenderadressene; bare mottakeren skrives om. VLAN-tagger (802.1Q, også stablede) fjernes fra IPv4-rammer, så de går ut utaggede også på en trunk-port; det finnes ikke noe valg for å beholde dem. Taggede ikke-IP-rammer (GOOSE, SV) beholder taggene. Ingen TCP-tilstand. | IDS, loggere, analyse av nettverkstrafikk |

Denne veiledningen handler om tilstandsfulle sesjoner.

---

## 2. Velg scenario

| Du tester | outstation spiller | Rolle i UI-et | Viktigste innstillinger |
|---|---|---|---|
| **A. En SCADA-master** (driftssentral, HMI-frontend som ringer opp RTU-er) | RTU-ene | *Target is a master* (slave-rolle) | Alias-NIC for RTU-adressene; gateway-modus hvis masteren når RTU-ene via standard gateway |
| **B. En RTU, en protokollgateway eller en server som mastere kobler seg til** | masteren(e) | *Target is a server* (master-rolle) | Mål-IP og port; utgående NIC mot målet |

I IEC 104 er den kontrollerte stasjonen (RTU-en) TCP-server og den kontrollerende stasjonen (masteren) TCP-klient. For å teste en master lytter altså outstation, og for å teste en RTU kobler outstation seg til.

---

## 3. Lab-topologi

Kjør outstation på en egen Linux-VM med to nettverkskort:

```
┌────────────────────────┐        ┌────────────────────────────┐
│  System under test     │        │  outstation (VM)           │
│  f.eks. SCADA-master   │        │                            │
│                        │        │  eth0 (indre)              │
│  eth0  10.0.0.50/24    ├────────┤  10.0.0.2/24               │
│  gw    10.0.0.1        │        │  + RTU-adresser som /32-   │
│                        │        │    alias under en kjøring  │
└────────────────────────┘        │  + 10.0.0.1/32 i gateway-  │
                                  │    modus, under kjøringen  │
       isolert vSwitch            │                            │
       "vswitch_test"             │  eth1 (ytre)               │
                                  │  10.20.30.40/24            │
                                  │  standard gw 10.20.30.1    │
                                  └─────────────┬──────────────┘
                                                │
                                          labnettet
                                     (admin, SSH, NTP, oppdateringer)
```

- **Isolert virtuell svitsj** (`vswitch_test`): en svitsj uten fysisk uplink. Bare systemet under test og outstations indre nettverkskort er koblet til den, så injisert trafikk kan ikke lekke ut i andre nett.
- **eth0 (indre)**: vender mot systemet under test. Gi det en ledig adresse i testsystemets subnett (her `10.0.0.2/24`), uten gateway.
- **eth1 (ytre)**: administrasjon og UI. Det har standardruten, så outstation beskytter det: kjøringer legger ikke alias-adresser på det og slaver det ikke inn i en bro, med mindre du overstyrer.

UI-et har ingen autentisering. Nå det via eth1 bare fra din egen arbeidsstasjon, eller bind det til loopback og bruk en SSH-tunnel ([drift](operations.md#the-systemd-unit)).

---

## 4. Gateway-modus: når SCADA-masteren står på et annet subnett

Dette gjelder scenario A når RTU-adressene i opptaket ikke ligger i masterens eget subnett.

**Problemet.** Masteren (si `10.0.0.50/24`, gateway `10.0.0.1`) ringer opp RTU `192.168.10.42:2404`. Adressen er utenfor subnettet, så masteren sender SYN-pakken til standard gateway: den spør med ARP etter `10.0.0.1`. På en isolert svitsj finnes det ingen ruter, og SYN-pakken havner ingen steder.

**De vanlige løsningene endrer noe du kanskje ikke får lov til å røre:** en statisk rute på masteren, eller en rute på labruteren som peker RTU-subnettene mot outstation. Styrer du labruteren selv, er en slik rute helt grei, og da trengs ikke gateway-modus.

**Gateway-modus** endrer bare masterens omgivelser. Så lenge kjøringen varer, legger outstation masterens standard gateway-IP (`10.0.0.1`) som `/32`-alias på sitt indre nettverkskort. På den isolerte svitsjen er outstation den eneste som svarer på masterens ARP etter gatewayen, så masteren sender all trafikk utenfor subnettet til outstation. Pakker til en RTU-adresse treffer det lokale RTU-aliaset og når lytteren til den avspilte RTU-en. Svarene går rett tilbake til `10.0.0.50`, som ligger på outstations direkte tilkoblede subnett.

Masteren blir ikke konfigurert om: den snakker fortsatt med «gatewayen sin», og RTU-adressene er de samme som i produksjon.

Valgfri **NAT oppstrøms**: oppgi det ytre nettverkskortet (`eth1`), så slår outstation også på IP-videresending og legger inn en merket MASQUERADE-regel der. Da når masteren fortsatt NTP, oppdateringer og lignende gjennom outstation under testen. La feltet stå tomt hvis masteren skal være helt isolert.

Alt gateway-modus gjør, blir journalført og tilbakestilt når kjøringen slutter. Gateway-modus nekter å bruke outstation-vertens egen standard gateway som gateway-IP.

**Gateway-modus gjelder bare slave-rollen** (scenario A, *Target is a master*). En kjøring i master-rolle (scenario B) som setter noen av gateway-feltene, blir avvist med `gateway_requires_slave`. I master-rollen har hver sesjon sin egen broport, og svarene må komme tilbake gjennom den porten. Et gateway-alias på det slavebundne nettverkskortet svarer ikke på ARP (kortet er en broport), og et alias på et annet kort trekker svarene bort fra sesjonens port, så sesjonene ville bare gått ut på tid. Skal du teste en enhet som når outstations sesjonsadresser via en ruter i master-rollen, legger du en rute på enheten under test eller på labruteren mot outstations nettverkskort, eller bruker opptatte mastere i enhetens eget subnett.

---

## 5. Scenario A: test av en SCADA-master

outstation spiller RTU-ene i opptaket. Hver RTU får en lytter på sin opptatte IP og port 2404 (*listen port base*). Alle lytterne deler porten; bare IP-adressen skiller dem, så masteren kan bruke RTU-listen fra produksjon uendret.

### 5.1 Sett opp kjøringen

Under **Configure**:

1. **Source pcap**: opptaket. Biblioteket viser hvor mange RTU-er det inneholder, og en vurdering av om det egner seg (`ok`, `caution`, `heavy`, `not_recommended`) med et anslag over minnebruken.
2. **Replay mode**: *Stateful session*. **Protocol**: `iec104`. **Role**: *Target is a master*.
3. **Master IP** (valgfritt): SCADA-masterens adresse. Den brukes til å finne nettverkskortet masterens trafikk kommer inn på, slik at den også blir tatt opp.
4. **Listen port base**: `2404`, med mindre masteren din bruker en annen port.
5. **Alias NIC for RTU listen IPs**: `eth0`, det indre kortet. RTU-adresser som ikke allerede finnes på verten, legges der som `/32 noprefixroute`-alias mens lytteren kjører. Uten dette ville aliasene havnet på kortet med standardruten, som er beskyttet, og de sesjonene feiler.
6. **Pacing**: *Original pcap timing* spiller av i opptakets takt (skalert med hastighetsfaktoren); *As fast as possible* tester gjennomstrømning.
7. **Iterations**: hvor mange ganger skriptet spilles (`0` = til du stopper). Kryss av for *Loop iterations within one TCP session* for å oppføre deg som en RTU som holder sesjonen åpen; ellers blir hver runde en ny forbindelse.
8. **IEC 104 options**:
   - *Fresh timestamps* skriver om CP56Time2a-tidsmerkene til det øyeblikket hver ramme sendes, så masteren ser aktuelle hendelsestider. Velg lokal tid eller UTC.
   - *Answer GI/CI live* (på som standard): de avspilte RTU-ene svarer selv på generelle utspørringer og telleverdi-utspørringer, ut fra punktverdiene i opptaket, og de opptatte utspørringssvarene tas ut av skriptet.
   - *IEC 104 link parameters*: k, w, t0–t3 og *Idle serve after script* (hvor lenge RTU-ene fortsetter å svare etter at skriptet er ferdig, standard 30 s).
   - Kommandoekko (på som standard) bekrefter masterens kommandoer slik en ekte RTU gjør. Tilbakemelding (return information) og feilinjeksjon legges i `proto_config`-JSON-en: se [IEC 104-referansen](iec104-config.md).
9. **SCADA gateway** (ved behov, [avsnitt 4](#4-gateway-modus-når-scada-masteren-står-på-et-annet-subnett)): kryss av for *Act as the SCADA side's gateway*, skriv inn masterens gateway-IP (`10.0.0.1`), velg `eth0` som *Inner NIC facing SCADA*, og eventuelt `eth1` som *Upstream NAT NIC*.
10. **RTUs to simulate**: velgeren viser alle RTU-ene i opptaket med antall meldinger og trafikkmengde. Begynn med én eller noen få RTU-er for å sjekke oppsettet, og kjør så hele flåten.

### 5.2 Start og følg med

1. Trykk **Start run**. Kjører noen andre allerede, får du en feilmelding som sier hvem som startet kjøringen og når; bare én kjøring kan være aktiv om gangen.
2. Kjøringen dukker opp under **Runs**. Lytterne venter i `pending`. Nå kan du koble til et opptaksverktøy hvis du vil, eller endre en lytte-IP.
3. Trykk **Start all pending** på kjøringskortet (eller start RTU-ene én og én i sesjonstabellen).
4. La masteren koble seg til. Hver sesjon går `listening → connected → active → completed`. Det levende diagrammet og sesjonstabellen viser meldingsrater per RTU.
5. Kjøringen slutter når alle sesjoner har spilt skriptet ferdig og ventetiden etterpå er ute, eller når du trykker **Stop**.

Når kjøringen er ferdig, analyseres den automatisk ut fra outstations eget opptak av RTU-sesjonene ([avsnitt 8](#8-slik-leser-du-resultatene)).

---

## 6. Scenario B: test av en RTU eller en server

outstation spiller masteren. Hver master i opptaket (hver klient-IP som snakker med målporten) blir én sesjon som kobler seg til **mål-IP-en** og spiller av masterens side av samtalen: STARTDT, utspørringer, kommandoer, klokkesynkronisering, kvitteringer.

**Én sesjon per master i opptaket.** Et opptak av én SCADA-master som spør 200 RTU-er gir **én** sesjon: masterens første samtale i opptaket som inneholder data fra masteren. Segmenter som mangler i opptaket, diskvalifiserer den ikke: sammensettingen skjøter bytene på hver side av hullet, sesjonen starter rammingen på nytt etter hullet og dropper rammer som krysser det, og sesjonens detaljer viser dette som **Capture gaps** (antall hull, hoppede bytes, droppede rammer). For å teste en bestemt RTU bruker du et opptak av den RTU-ens forbindelse (filtrer pcap-en først om nødvendig). Opptak med flere mastere, for eksempel en frontend som betjener flere driftssentraler, gir én sesjon per master; velgeren (*Masters to replay*) lar deg velge blant dem.

### 6.1 Nettverk

Hver sesjon får sin egen veth-port på en privat bro, med den opptatte masterens IP- og MAC-adresse, og binder socketen sin til den porten. Broen slaver inn det **utgående nettverkskortet** (`eth0`, det indre kortet), så sesjonene dukker opp på testsegmentet med de opptatte adressene.

Målet må nå disse adressene på det segmentet: det spør med ARP, og hver port svarer for sin egen adresse. Det fungerer når:

- master-adressene i opptaket ligger i målets subnett; eller
- du setter **Master bind IP** til en ledig adresse i målets subnett, som alle sesjonene da bruker; eller
- målets rute til master-subnettet peker direkte ut på testsegmentet.

Kjøringens grensesnitt er isolert fra verten: ingen videresending, streng ARP, IPv6 av, og merkede brannmurregler som kaster alt som kommer inn på dem, unntatt målets svar til en sesjonsadresse.

### 6.2 Sett opp og kjør

1. **Replay mode**: *Stateful session*. **Role**: *Target is a server*.
2. **Target IP** og **Target port** (`2404`): RTU-en eller serveren som testes.
3. **Egress NIC**: `eth0`. Er kortet beskyttet (det har standardruten, eller adressen du nådde UI-et på), avvises kjøringen med mindre du overstyrer beskyttelsen under **Safety**. I den anbefalte topologien er det indre kortet ikke beskyttet.
4. **Session start**: *All sessions at once*, eller *Staggered to pcap timing* for å starte hver master på sitt tidspunkt i opptaket.
5. **Pacing**, **Iterations** og **IEC 104 options** som i scenario A. GI/CI-svar og kommandoekko gjelder bare slave-rollen; i master-rollen sendes de opptatte kommandoene, og tiden til målets bekreftelser måles.
6. **Start run**. Sesjonene kobler seg til, spiller skriptet, sender gjenstående kvitteringer, sender STOPDT og lukker.

Rå avspilling og master-rollen tar opp trafikken ved å speile kjøringens porter, og det krever `tc` på verten ([drift](operations.md#troubleshooting)).

---

## 7. Oppsett av labben steg for steg

Dette gjør du én gang per lab.

### 7.1 Lag den isolerte svitsjen

**VMware vSphere / ESXi:**

1. *Host → Networking → Virtual switches → Add standard virtual switch*, kall den `vswitch_test`.
2. **Ikke koble til noen fysisk uplink.**
3. *Port groups → Add port group*, kall den `pg_scada_test`, på `vswitch_test`, VLAN 0.

**Proxmox VE:**

1. *Datacenter → Node → Network → Create → Linux Bridge*, kall den `vmbr_test`.
2. La *Bridge ports* stå tomt, og gi den ingen IP.

**libvirt / virt-manager:**

```xml
<network>
  <name>isolated-test</name>
  <forward mode='none'/>
  <bridge name='virbr-test' stp='on'/>
</network>
```

```sh
sudo virsh net-define isolated.xml && sudo virsh net-start isolated-test && sudo virsh net-autostart isolated-test
```

### 7.2 Flytt systemet under test over på svitsjen

1. Slå av VM-en, eller bytt nettverkskort mens den kjører hvis hypervisoren støtter det.
2. Endre nettverkskortet til `pg_scada_test` / `vmbr_test` / `isolated-test`.
3. Endre ingenting inne i gjesten: adresse, nettmaske, gateway og DNS blir som før.
4. Start den igjen. Den har ingen forbindelse før outstation også er koblet til; det er som forventet.

### 7.3 Lag outstation-VM-en

1. En Linux-VM (for eksempel Ubuntu Server LTS). Vurderingen av opptaket anslår hvor mye minne en kjøring trenger; kjøringen med 165 RTU-er i [reports/](../reports/README.md) brukte en VM med 12 vCPU og 12 GB.
2. To nettverkskort: `eth0` på den isolerte svitsjen, `eth1` på labnettet.
3. `eth0`: en ledig statisk adresse i testsystemets subnett, uten gateway. `eth1`: labadresse og standard gateway.
4. Installer verktøyene tjenesten trenger: `iproute2`, `iptables`, `ethtool`, og `iputils-arping` for ARP-oppslaget i UI-et.
5. Bygg og installer:

   ```sh
   cargo build --release -p outstation
   sudo ./systemd/install.sh
   ```

6. Sjekk forbindelsen: `ping 10.0.0.50` fra outstation.

### 7.4 Åpne UI-et

Åpne `http://<eth1-adresse>:8080`. Toppen av siden viser serverens helsetilstand; en advarsel der (for eksempel manglende rettigheter eller lite diskplass) er forklart i [drift](operations.md#health-and-metrics).

---

## 8. Slik leser du resultatene

### 8.1 Kjøringen

Kjøringskortet viser status (`completed`, `partial` når noen sesjoner feilet, `stopped`, `failed`), sendte og mottatte meldinger, og nedlasting av opptaket. **Details** viser i tillegg:

- **Ack latency** min/p50/p90/p99/maks: tiden fra en I-ramme sendes til motparten kvitterer, over alle sesjoner, med histogram. I scenario A gjenspeiler dette mest masterens egne `w` og `t2`: den kvitterer etter `w` I-rammer eller `t2` etter den første ukvitterte, så glissen telemetri gir forsinkelser nær masterens `t2`. Det er ikke rundturstid i nettet ([detaljer](iec104-config.md#session-report-fields)). Linjen **Peer ack cadence** under viser hvilken regel som utløste kvitteringene (fullt vindu, t2-timeren eller N(R) i motpartens egne I-rammer), og sier fra når de fleste kom på timeren.
- **Per sesjon**: sendte og mottatte meldinger, forsinkelsesprosentiler, meldinger per sekund, **window stalls** (hvor ofte sesjonen ventet fordi motparten ikke hadde kvittert for k rammer; et høyt tall betyr at motparten er treg med kvitteringene), **unacked at end**, og eventuell feilmelding.
- **Gap-histogrammet** sammenligner avstanden mellom rammene i kilden og i avspillingen.

### 8.2 Analysen

Alle ferdige tilstandsfulle kjøringer med opptak analyseres automatisk. **Analysis** viser de lagrede analysene for en kjøring; du kan også laste opp et opptak tatt på målsiden med Wireshark eller tcpdump.

- **Dom for hele flåten**: `all_correct`, `stopped_clean` (kjøringen ble stoppet; det som ble sendt før stoppet var feilfritt), `partial`, `failed`, `inconclusive`, eller `run_failed` når selve kjøringen feilet eller ikke sendte noe.
- **Per RTU**: poengsum (andelen rammer levert uendret), dom og begrunnelse. `good_delivery` er godkjent; `degraded` betyr at innholdet var riktig, men tidsmerker, GI/CI-revisjonen eller timingen feilet; `partial_delivery` betyr at rammer manglet, kom i tillegg, var endret eller kom i feil rekkefølge; `never_connected` betyr at masteren aldri koblet seg til den RTU-en.
- **Domsdimensjoner** per RTU: innhold, tidsmerker, GI/CI, timing, handshake, og feil når slike ble injisert.
- **GI/CI-revisjon**: for hver utspørring masteren sendte, om ActCon kom innen 15 s, om alle datarammer hadde riktig gruppe-COT, om ActTerm fulgte, og om dataene stemte med RTU-ens punktverdier.
- **Timing**: varighet i opptaket mot avspillingen, en hastighetsmerkelapp («matched» innenfor ±5 %) og taktavvik.
- **CP56-avvik** (med ferske tidsmerker): hvert tidsmerke mot det faktiske sendetidspunktet.

Den fullstendige listen over dommer står i [IEC 104-referansen](iec104-config.md#analysis-report).

---

## 9. Repeterbare tester: profiler, ny kjøring, sammenligning, CI

- **Ny kjøring**: `POST /api/runs/<id>/rerun` starter en ny kjøring med nøyaktig den lagrede forespørselen fra en tidligere kjøring. Overstyring av beskyttelsen arves aldri.
- **Profiler**: lagre en kjøringsforespørsel under et navn (`/api/profiles`) og bruk den igjen.
- **Sammenligning**: `GET /api/runs/<a>/compare/<b>` gir forskjellene for hele flåten og per RTU i poengsum, leverte rammer, forsinkelse og gjennomstrømning, og flagger tilbakegang ut over terskler du velger. Bruk det før og etter en oppgradering av systemet under test.
- **CI**: `outstation bench` kjører én benchmark fra en profil, analyserer den og sjekker påstander:

  ```sh
  sudo outstation bench --pcap fleet.pcap --profile master-test.json \
      --assert 'score>=99' --assert 'p99_ms<=500' --report out.json
  ```

  Avslutningskode 0 betyr at alle påstandene holdt, 1 at en påstand feilet, 2 at kjøringen feilet.

Ny kjøring, profiler og sammenligning finnes i UI-et (kjøringskort, Konfigurer → Profiler og Sammenlign-visningen), i API-et og i `bench`. Se [API-referansen](api.md) for eksempler; skript må sende en `Origin`-header.

---

## 10. Opprydding og sikkerhet

Hver endring en kjøring gjør på outstation-verten (broer og veth-par, IP-alias, gateway-aliaset, videresending, NAT- og brannmurregler, innstillinger på nettverkskort) skrives først til en journal og tilbakestilles når kjøringen slutter. Etter et krasj rydder tjenesten opp det som ble liggende igjen når den starter på nytt, og systemd-enheten kjører `outstation cleanup` hver gang tjenesten stopper. Du kan kjøre `sudo outstation cleanup` for hånd mens tjenesten er stoppet.

Systemet under test endres aldri. outstation sender likevel trafikk med falske avsenderadresser, så hold testsegmentet isolert, og test bare systemer du har lov til å teste.

---

## 11. Feilsøking

### Masteren når ikke RTU-ene (scenario A)

På outstation, mens kjøringen pågår:

```sh
ip addr show eth0              # RTU-adresser som /32, og gateway-IP-en i gateway-modus
ip neigh | grep 10.0.0.50      # masterens MAC-adresse
sudo tcpdump -ni eth0 port 2404
```

- Ingen SYN-pakker i det hele tatt: masteren sender ikke til outstation. Sjekk at den står på den isolerte svitsjen, og i gateway-modus at gateway-IP-en er dens faktiske standard gateway (`ip route` på masteren; å lese den endrer ingenting).
- SYN kommer, men ingen SYN-ACK: RTU-ens lytter er ikke oppe. Sjekk at den er startet (**Start all pending**), og se på sesjonens feilmelding. «needs a /32 alias on …» betyr at alias-kortet mangler eller er beskyttet.
- Masteren avviser sesjonen: hvitelisten dens inneholder ikke RTU-adressene fra opptaket. Bruk et opptak fra samme miljø.

### Målet svarer aldri (scenario B)

- `tcpdump -ni eth0 port 2404` på outstation: går SYN-pakkene ut med master-adressen fra opptaket?
- Svarer målet på ARP for den adressen? Ligger master-IP-en utenfor målets subnett, bruk **Master bind IP** ([avsnitt 6.1](#61-nettverk)).
- «connect timeout»: øk `t0` under IEC 104-linkparameterne (standard 5 s her).

### Sesjoner faller ut med `t1_timeout`

Motparten kvitterte ikke innen t1 (15 s som standard). Den kan være overbelastet eller ha et mindre vindu; `protocol_errors` og `window_stalls` for sesjonen forteller mer. Juster k, w og tidsfristene til motpartens konfigurasjon.

### Kjøringen avvises

- 409 «run … is active»: noen andre har en aktiv kjøring.
- Et nettverkskort er «protected»: du valgte kortet med standardruten eller det du nådde UI-et på. Velg det indre kortet, eller overstyr beskyttelsen hvis det er det du mener.

### Masteren mister internett under testen

Gateway-modus uten NAT oppstrøms isolerer den. Legg til `eth1` som NAT-kort oppstrøms, eller godta isolasjonen (ofte det beste valget).

### outstation krasjet

Start den på nytt (`sudo systemctl restart outstation`); oppstarten rydder opp etter den krasjede kjøringen. Tjenesteloggen viser hva som ble tilbakestilt.

Mer i [drift](operations.md#troubleshooting).

---

## 12. Ordliste

| Begrep | Betydning |
|---|---|
| **IEC 60870-5-104** | SCADA-protokoll for fjernkontroll over TCP, port 2404. Overfører I-, S- og U-rammer med k/w-flytkontroll |
| **Kontrollerende stasjon (master)** | SCADA-siden som samler inn data og sender kommandoer. I IEC 104 er den TCP-**klient** |
| **Kontrollert stasjon (RTU, slave)** | Feltstasjonen som rapporterer data og utfører kommandoer. I IEC 104 er den TCP-**server** |
| **Slave-rolle** | outstation spiller RTU-ene og lytter; systemet under test er en master (scenario A) |
| **Master-rolle** | outstation spiller masteren og kobler seg til; systemet under test er en RTU eller en server (scenario B) |
| **I-ramme** | Informasjonsramme med en ASDU (måleverdier, hendelser, kommandoer) |
| **S-ramme** | Kvitteringsramme for mottatte I-rammer |
| **U-ramme** | Kontrollramme: STARTDT, STOPDT, TESTFR |
| **k / w** | Høyst k ukvitterte I-rammer underveis (standard 12); kvitter senest etter w mottatte (standard 8) |
| **t1 / t2 / t3** | Tidsfrist for kvittering (15 s), seneste kvitteringsforsinkelse (10 s), stille tid før TESTFR (20 s) |
| **ASDU** | Applikasjonsdataenhet: type-ID, årsak til overføring (COT), felles adresse (CA), objektadresse (IOA), verdier |
| **GI / CI** | Generell utspørring (type 100) og telleverdi-utspørring (type 101): masteren ber om alle gjeldende verdier |
| **CP56Time2a** | Tidsmerket på 7 oktetter i tidsmerkede ASDU-er |
| **Isolert vSwitch** | En virtuell svitsj uten fysisk uplink |
| **/32-alias** | En ekstra enkeltadresse på et nettverkskort, uten subnettrute |
| **MASQUERADE** | NAT-regel som skriver om avsenderadressen til adressen på det utgående kortet |

---

- Oversikt over prosjektet: [README](../README.md)
- [HTTP-API](api.md), [IEC 104-referanse](iec104-config.md), [Drift](operations.md)
