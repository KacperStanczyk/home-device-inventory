# CLI wspólnego rejestru urządzeń

## Zakres repozytorium i wymagania

To repozytorium zawiera kod CLI, schemat, migracje, testy i instrukcje. Nie
zawiera bazy `vault/`, kopii bazy, artefaktów, obrazów firmware ani danych
dostępu. Te pliki są lokalne i nie mogą wejść do Git.

Podstawowa kontrola wymaga Python 3 z modułem `sqlite3`. Operacje urządzeń
wymagają Linux oraz tylko potrzebnych programów: `pm3` dla Proxmark3, `ssh`
dla Raspberry Pi, `nmcli` i `zenity` dla Gree oraz `udevadm` i `setfacl` dla
naprawy uprawnień portu. Testy używają sztucznego klienta Proxmark3.

Nie dodawaj lokalnych źródeł Proxmark3 do tego repozytorium. Użyj klienta
`pm3` z `PATH` albo osobnego, przypiętego checkoutu upstream. Dla wersji
firmware `v4.20728` użyj tagu upstream `RfidResearchGroup/proxmark3`.

Niektóre operacje Raspberry Pi są opcjonalną lokalną zależnością w sąsiednim
katalogu `../Raspberry`. Ten katalog nie jest częścią publicznego repozytorium.
Nie kopiuj z niego skryptów, które odczytują hasła, tokeny lub inne sekrety.
Bez tego katalogu `init` nadal tworzy bazę, ale nie rejestruje prywatnego
skryptu Raspberry Pi.

Główny punkt wejścia to:

```bash
./rfid_vault.py COMMAND
```

CLI zarządza lokalnym rejestrem urządzeń domowych. Moduł Proxmark3 pozostaje
osobną częścią CLI. Przed kontaktem z urządzeniem sprawdź projekt, urządzenie i
aktywną autoryzację.

Schemat v7 jest wymagany. Pierwsze uruchomienie na bazie v5 albo v6:

```bash
./rfid_vault.py init
```

Polecenie wykonuje kolejne migracje v5 → v6 → v7 albo v6 → v7. Każda migracja
ma wpis z SHA-256 w `schema_migrations`. CLI nie obsługuje starszych schematów.
Baza pozostaje lokalna i ma tryb pliku `0600`.

## Kopia i odtworzenie bazy

Kopia jest plikiem SQLite i prywatnym plikiem manifestu JSON. CLI sprawdza
integralność SQLite oraz SHA-256 przed rejestracją kopii. Dla głównej bazy
domyślny katalog to `vault/backups`.

```bash
./rfid_vault.py database-backup
./rfid_vault.py database-backups
./rfid_vault.py database-backup --output vault/backups/home-before-change.sqlite3
```

Odtworzenie zastępuje bazę. CLI najpierw tworzy automatyczną kopię ochronną,
potem sprawdza wybraną kopię i jej manifest. Użyj jawnego potwierdzenia:

```bash
./rfid_vault.py database-restore \
  --backup vault/backups/home-before-change.sqlite3 \
  --confirm
```

## Zasada nadrzędna: operacje tylko przez CLI

Każda powtarzalna operacja urządzenia zaczyna się w `rfid_vault.py`. Najpierw
użyj istniejącego polecenia. Jeśli go nie ma, dodaj jedno polecenie CLI i test.
Nie twórz drugiego skryptu SSH, curl, portu szeregowego lub Proxmark3 poza CLI.

Skrypt pomocniczy może zawierać tylko szczegóły jednej operacji. Zarejestruj go
w bazie. CLI sprawdza autoryzację, uruchamia go bez `shell=True`, ogranicza czas
i zapisuje metadane audytu. Wynik skryptu nie jest zapisywany w SQLite, bo może
zawierać sekret.

Każdy zarejestrowany skrypt musi odrzucić brak zmiennych
`DEVICE_CLI_CONTEXT` i `DEVICE_CLI_SCRIPT_KEY`. CLI sprawdza tę ochronę przy
rejestracji i przed uruchomieniem. Rejestr zapisuje też SHA-256 oraz numer
rewizji skryptu. Zmiana pliku blokuje wykonanie. Po przeglądzie zarejestruj
skrypt ponownie przez `device-script-add`.

```bash
./rfid_vault.py device-script-add \
  --device computer:raspberry-pi-3 \
  --key raspberry.health.read \
  --name "Read Raspberry health" \
  --description "Read current throttling and temperature." \
  --path ../Raspberry/read-raspberry-health.sh \
  --operation inspect \
  --risk read_only

./rfid_vault.py device-scripts --device computer:raspberry-pi-3
./rfid_vault.py device-script-run raspberry.health.read \
  --project home-infrastructure \
  --device computer:raspberry-pi-3
```

`device-script-run` nie przyjmuje dowolnych argumentów skryptu. Jeśli operacja
potrzebuje danych wejściowych, dodaj jawne, bezpieczne opcje do CLI oraz test.

CLI przekazuje aktywny adres i endpoint urządzenia jako
`DEVICE_CLI_DEVICE_ADDRESS` i `DEVICE_CLI_DEVICE_ENDPOINT`. Dla istniejących
skryptów Raspberry Pi przekazuje też adres jako `RASPBERRY_HOST`. Dzięki temu
brak lokalnego mDNS nie omija kontroli autoryzacji ani audytu.

Pełny test obciążeniowy Raspberry Pi jest poleceniem zarządzanym. Test zapisuje
plik tymczasowy, sprawdza sieć, obciąża CPU i RAM oraz stale kontroluje
temperaturę i flagi zasilania. Limit temperatury wynosi 76°C. Próbka ma
odstęp jednej sekundy.

```bash
./rfid_vault.py device-script-run raspberry.stress.test \
  --project home-infrastructure \
  --device computer:raspberry-pi-3
```

Wykrywanie klimatyzatora Gree jest operacją tylko do odczytu. Polecenie
sprawdza SSID trybu parowania na 2,4 GHz. Potem wysyła tylko pakiet
`{"t":"scan"}` przez UDP 7000. Polecenie nie wysyła `bind`, `status` ani
`cmd`. Urządzenie Gree i autoryzacja `identify` muszą być aktywne.

```bash
./rfid_vault.py device-script-run gree.wifi.discover \
  --project home-infrastructure \
  --device appliance:example-gree-air-conditioner
```

Jeżeli PC nie widzi urządzenia, wykonaj ten sam, sprawdzony skan z Raspberry
Pi. CLI najpierw sprawdza autoryzację Pi i Gree. Skrypt używa ścisłej kontroli
klucza SSH. Nie zapisuje pliku na Raspberry Pi.

```bash
./rfid_vault.py device-script-run raspberry.gree-wifi.discover \
  --project home-infrastructure \
  --device computer:raspberry-pi-3
```

Provisioning bez GREE+ jest interaktywną zmianą konfiguracji. Polecenie pokazuje
lokalne okna wyboru i hasła. Nie podawaj hasła w czacie. Skrypt pobiera sekret
do pamięci, łączy PC z punktem Gree, wysyła jeden datagram `wlan`, wraca do
poprzedniego profilu Wi-Fi i usuwa profil tymczasowy. Hasło nie trafia do
argumentów, zmiennych środowiska, SQLite ani audytu. Lista może zawierać
niezapisaną sieć tego samego routera, jeżeli nadaje na 2,4 GHz z czystym WPA2.
Wtedy hasło tej sieci podaj tylko w ukrytym oknie.

```bash
./rfid_vault.py device-script-run gree.wifi.provision \
  --project home-infrastructure \
  --device appliance:example-gree-air-conditioner
```

## Katalog urządzeń

Pokaż typy urządzeń:

```bash
./rfid_vault.py device-types
```

Dodaj własny typ. Typ określa dopuszczalny ogólny rodzaj urządzenia:

```bash
./rfid_vault.py device-type-add \
  --key sensor.humidity \
  --name "Humidity sensor" \
  --category sensor \
  --kind embedded_device \
  --description "Sensor that reports relative humidity."
```

Opcjonalny kontrakt typu definiuje możliwości oraz dane. Tryb `strict` blokuje
niezdefiniowane informacje i kanały pomiaru. Tryb `advisory` zapisuje kontrakt,
ale nie blokuje rozszerzeń.

```bash
./rfid_vault.py device-type-contract-set \
  --type sensor.humidity \
  --enforcement strict \
  --capabilities-json '["measure.humidity"]' \
  --information-schema-json '{"measurement_precision":{"information_kinds":["fact"],"unit":"percent","value_type":"number"}}' \
  --measurement-schema-json '{"humidity.percent":{"maximum":100,"minimum":0,"quantity_kind":"humidity","unit":"percent"}}' \
  --source sensor-datasheet

./rfid_vault.py device-type-contracts --type sensor.humidity
```

Dodaj urządzenie. Wynik ma stan `pending_authorization`:

```bash
./rfid_vault.py device-add \
  --project home-infrastructure \
  --key sensor:humidity-salon \
  --name "Salon humidity sensor" \
  --kind embedded_device \
  --type sensor.humidity \
  --role support \
  --ownership household_owned
```

Pokaż urządzenie. Wartości wrażliwe są ukryte domyślnie:

```bash
./rfid_vault.py devices --project home-infrastructure
./rfid_vault.py device-show --device computer:raspberry-pi-3
./rfid_vault.py device-show --device computer:raspberry-pi-3 --reveal-sensitive
```

## Informacje, interfejsy i relacje

Każda informacja ma źródło. `--value-json` musi być prawidłowym JSON:

```bash
./rfid_vault.py device-information-set \
  --device sensor:humidity-salon \
  --kind fact \
  --property measurement_precision \
  --value-json 2.0 \
  --unit percent \
  --source sensor-datasheet \
  --confidence verified

./rfid_vault.py device-identifier-add \
  --device sensor:humidity-salon \
  --kind serial.number \
  --value "SENSOR-001" \
  --classification sensitive \
  --source owner-record

./rfid_vault.py device-interface-set \
  --device sensor:humidity-salon \
  --key i2c.bus1 \
  --type i2c \
  --address "0x76" \
  --source wiring-record

./rfid_vault.py device-relation-add \
  --source-device sensor:humidity-salon \
  --target-device computer:raspberry-pi-3 \
  --type connected_to \
  --source wiring-record
```

`--type` musi być aktywnym terminem ze słownika. Pokaż terminy lub dodaj nowy:

```bash
./rfid_vault.py relation-types
./rfid_vault.py relation-type-add \
  --type reports_to \
  --name "Reports to" \
  --description "The source device reports data to the target device."
```

Nie używaj nazw informacji takich jak `password`, `token` lub `secret`. CLI je
blokuje. Dla technicznej metody dostępu użyj tylko referencji do sekretu:

```bash
./rfid_vault.py access-method-set \
  --project home-infrastructure \
  --device computer:raspberry-pi-3 \
  --key ssh \
  --type ssh \
  --endpoint raspberry.example.invalid:22 \
  --authentication-type ssh_public_key \
  --secret-reference keyring:raspberry-pi-ssh-key
```

`access-method-set` nie daje autoryzacji. Użyj `access-grant` dopiero po
potwierdzeniu podstawy dostępu.

## Pomiary

Najpierw dodaj kanał. Kanał ma jednostkę i opcjonalny zakres:

```bash
./rfid_vault.py measurement-channel-add \
  --device sensor:temperature-salon \
  --key temperature.c \
  --name Temperature \
  --quantity temperature \
  --unit degC \
  --minimum -40 \
  --maximum 125 \
  --retention-days 365 \
  --source sensor-datasheet

./rfid_vault.py measurement-add \
  --device sensor:temperature-salon \
  --channel temperature.c \
  --observed-at "2026-08-15T12:00:00+02:00" \
  --value 22.5 \
  --source "manual-read:temperature-salon"

./rfid_vault.py measurements \
  --device sensor:temperature-salon \
  --channel temperature.c
```

`retention_days` zapisuje politykę kanału. Najpierw pokaż plan. Usunięcie
wymaga dwóch jawnych opcji i zapisuje audyt z liczbą kandydatów oraz usunięć:

```bash
./rfid_vault.py measurement-retention
./rfid_vault.py measurement-retention --apply --confirm
```

Wynik poleceń urządzeń może zawierać dane wrażliwe. Po 90 dniach CLI może
usunąć tylko treść wyniku, ale zachowa jego pierwotny SHA-256:

```bash
./rfid_vault.py audit-output-retention
./rfid_vault.py audit-output-retention --apply --confirm
```

## Dostęp

```bash
./rfid_vault.py access-grant \
  --project home-infrastructure \
  --device sensor:temperature-salon \
  --key authorization:temperature-salon \
  --subject project_owner \
  --basis household_owner \
  --level read \
  --operation read \
  --purpose home \
  --evidence "owner-record:temperature-salon" \
  --valid-from "2026-08-15T00:00:00+02:00"

./rfid_vault.py access-check \
  --project home-infrastructure \
  --device sensor:temperature-salon
```

Kod wyjścia `0` oznacza aktywną autoryzację. Kod `2` oznacza jej brak.

## RFID i Proxmark3

Dane RFID są osobne, lecz każdy profil RFID wskazuje wpis `devices`. Użyj
`rfid-profile-set` dla ręcznie dodanego urządzenia RFID. Pełny odczyt MIFARE
Classic dodawaj tylko przez `import-mfc`.

Przed `access-grant` dla czytnika, karty, taga lub breloka dodaj profil RFID.
CLI blokuje aktywną autoryzację bez tego profilu.

`list` i `show` ukrywają UID oraz bloki producenta. Użyj `show ID
--reveal-sensitive` tylko w uprawnionej lokalnej sesji. Klucze sektorów wymagają
dodatkowo `--reveal-keys`.

CLI preferuje wersję klienta zapisaną dla czytnika w SQLite. Zapobiega to błędowi
protokołu możliwości między nowym klientem i starszym firmware. Jawne `--client`
lub zmienna `RFID_PM3_CLIENT` mają pierwszeństwo podczas diagnostyki.

### Diagnostyka

```bash
./rfid_vault.py pm3-probe
./rfid_vault.py pm3-probe --json
```

Stan `READY` oznacza, że CLI może połączyć się z urządzeniem. Stan `NOT READY` zawiera problem i czynność naprawczą.

### Proxmark3 przez Raspberry Pi

Gdy Proxmark3 jest podłączony przez USB do autoryzowanego Raspberry Pi, użyj
transportu `raspberry-ssh`. CLI sprawdza aktywną autoryzację czytnika oraz
Raspberry Pi, aktywną ścieżkę SSH w rejestrze, klucz hosta SSH i zdalny port
szeregowy. Nie używaj ręcznego `ssh` ani zdalnego klienta Proxmark3 poza CLI.

Najpierw dodaj techniczną ścieżkę do wpisu czytnika. Endpoint musi być taki sam
jak aktywny endpoint SSH Raspberry Pi. To nie zmienia firmware ani danych RFID.

```bash
./rfid_vault.py access-method-set \
  --project rfid-home-lab \
  --device reader:example-proxmark3-reader \
  --key raspberry-pi-ssh \
  --type ssh \
  --endpoint raspberry.example.invalid:22 \
  --account-label inventory-user \
  --authentication-type ssh_public_key \
  --notes "Proxmark3 USB transport through the registered Raspberry Pi"
```

Potem uruchom standardową sekwencję. `pm3-probe` tylko sprawdza zdalną ścieżkę,
klienta i uprawnienia do `/dev/ttyACM0`. `pm3-run` uruchamia wyłącznie nazwane
polecenie z `device_commands` i zapisuje audyt na wpisie czytnika.

```bash
./rfid_vault.py pm3-probe --via raspberry-ssh
./rfid_vault.py pm3-run pm3.hw-version --via raspberry-ssh
./rfid_vault.py pm3-run pm3.hf-search --via raspberry-ssh
```

Transport zdalny obecnie obsługuje `pm3-probe` i `pm3-run`. Backup pamięci i
flash firmware pozostają lokalne, ponieważ wymagają osobnego, kontrolowanego
transferu pliku. Nie używaj ich przez ręczne SSH.

### Uprawnienia portu Linux

Pokaż plan naprawy:

```bash
./rfid_vault.py pm3-fix-permissions
```

Zastosuj plan w interaktywnym terminalu:

```bash
./rfid_vault.py pm3-fix-permissions --apply
```

Ta operacja może poprosić o hasło `sudo`. Dodaje użytkownika do grupy `dialout`, instaluje regułę udev i nadaje bieżącej sesji dostęp ACL, jeśli `setfacl` jest dostępny. Po ponownym podłączeniu urządzenia może być wymagane wylogowanie i ponowne zalogowanie.

### Polecenia wielokrotnego użycia

Lista:

```bash
./rfid_vault.py pm3-commands
```

Wykonanie:

```bash
./rfid_vault.py pm3-run pm3.hw-version
./rfid_vault.py pm3-run pm3.hw-status
./rfid_vault.py pm3-run pm3.hw-tune
./rfid_vault.py pm3-run pm3.hf-search
./rfid_vault.py pm3-run pm3.lf-search
./rfid_vault.py pm3-run pm3.lf-read
./rfid_vault.py pm3-run pm3.auto-scan
```

`pm3.lf-read` sprawdza pobieranie próbek LF bez opcjonalnych testów chipsetów. Użyj go, gdy starszy firmware nie obsługuje polecenia `CMD_LF_HITAGU_UID` używanego przez pełne `lf search`.

CLI sprawdza też sens fizyczny wyniku `hw tune`. Niemożliwa wartość napięcia HF powoduje błąd diagnostyczny, nawet jeśli klient Proxmark3 zwróci kod 0.

### Kopia i aktualizacja firmware

Najpierw wykonaj kopię pamięci MCU:

```bash
./rfid_vault.py pm3-firmware-backup \
  --output vault/backups/proxmark3-before-update.bin
```

Kopia wymaga autoryzacji `inspect`. CLI sprawdza rozmiar pliku, ustawia prawa `0600`, oblicza SHA-256 i zapisuje wykonanie w audycie.

Bezpieczna kolejność dla Proxmark3 Easy jest następująca:

```bash
./rfid_vault.py pm3-firmware-flash \
  --fullimage proxmark3-v4.20728/armsrc/obj/fullimage.elf \
  --confirm

./rfid_vault.py pm3-run pm3.hw-version
./rfid_vault.py pm3-run pm3.hw-status

./rfid_vault.py pm3-firmware-flash \
  --bootrom proxmark3-v4.20728/bootrom/obj/bootrom.elf \
  --confirm
```

Najpierw flashuj tylko `fullimage`. Sprawdź uruchomienie urządzenia i zewnętrzną pamięć SPI. Dopiero potem flashuj `bootrom`. Obie operacje wymagają autoryzacji `configure` i jawnego `--confirm`. Obrazy muszą mieć format ELF. CLI zapisuje ich skróty SHA-256 w audycie.

Opcja `--force` jest dozwolona tylko dla kontrolowanego przejścia wersji, gdy klient zgodny ze starym bootloaderem flashuje sprawdzony obraz nowej wersji. CLI zapisuje użycie tej opcji w audycie.

Dodanie nowego polecenia:

```bash
./rfid_vault.py pm3-command-add \
  --key pm3.example \
  --name "Example command" \
  --description "Describe one repeatable operation." \
  --command "hw version" \
  --operation inspect \
  --risk read_only \
  --timeout 30
```

Użyj poziomu ryzyka `state_change` lub `destructive`, gdy polecenie zmienia dane lub stan urządzenia.

### Audyt

```bash
./rfid_vault.py pm3-history --limit 20
```

Tabela `device_command_runs` zapisuje status, czas, kod wyjścia, skróty SHA-256 i pełny wynik procesu. Baza jest poufna i ma prawa `0600`.

### Reguła rozwoju

Jeśli potrzebna operacja nie ma nazwanego polecenia, najpierw sprawdź ją diagnostycznie. Następnie dodaj ją do CLI, dokumentacji i testów. Jeśli CLI ma problem, napraw problem w CLI. Nie pozostawiaj stałego ręcznego obejścia.

### Test E2E CLI

`RFIDVaultCLIEndToEndTests` uruchamia wszystkie polecenia parsera na osobnej
bazie SQLite. Test używa sztucznego klienta Proxmark3 i tymczasowych danych
MIFARE. Nie używa Raspberry Pi, sekretów ani realnego firmware.

```bash
python3 -m unittest -v test_rfid_vault.RFIDVaultCLIEndToEndTests
```

Test porównuje listę uruchomionych poleceń z aktualnym parserem. Nowe polecenie
wymaga więc rozszerzenia testu E2E.
