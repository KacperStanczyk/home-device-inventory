# Home Device Inventory

## Git i dane prywatne

Repozytorium Git zawiera tylko kod, schemat, migracje, testy i instrukcje.
Katalog `vault/` jest lokalny. Zawiera bazę, kopie, artefakty i obrazy
firmware. Nie dodawaj go do GitHub.

Źródła Proxmark3 są zależnością zewnętrzną GPLv3. Zachowaj je poza tym
repozytorium albo użyj przypiętego submodule. Zarejestruj każdą lokalną zmianę
upstream jako osobny patch z informacją o wersji i licencji.

Skrypty z `../Raspberry` są opcjonalną lokalną zależnością środowiska domu.
Nie są częścią publicznego repozytorium. Skrypt, który może odczytać sekret,
musi pozostać lokalny i nie może wejść do historii Git.

## Cel

Projekt jest lokalnym rejestrem prywatnych urządzeń domowych, dostępu do nich,
pomiarów i chronionych danych RFID. Główna baza to
`vault/rfid_inventory.sqlite3`. Nazwa pliku jest historyczna. Zawartość jest
wspólnym katalogiem urządzeń domowych.

Schemat ma wersję 7. Polecenie `init` wykonuje migrację v5 → v6 → v7 albo
v6 → v7. Tabela `schema_migrations` zapisuje wersję, czas i SHA-256 skryptu.
Starsze schematy nie są obsługiwane.

## Zasada nadrzędna CLI

`rfid_vault.py` jest jedyną zwykłą ścieżką dla powtarzalnej operacji urządzenia.
Nowa potrzeba oznacza: użyj istniejącego polecenia albo dodaj jedno polecenie
CLI, rejestr skryptu, audyt i test. Nie twórz drugiej ścieżki przez SSH, curl,
port szeregowy lub klienta urządzenia.

`device_scripts` zawiera zatwierdzone lokalne skrypty z SHA-256 i numerem
rewizji. `device-script-run` sprawdza hash i autoryzację przed uruchomieniem,
ogranicza czas i zapisuje tylko metadane. Zmiana pliku blokuje uruchomienie do
ponownej rejestracji. Wynik skryptu nie trafia do SQLite. Jest to ważne dla
danych dostępu.

## Zasada autoryzacji

System stosuje zasadę odmowy domyślnej. Rejestracja urządzenia nie daje prawa do
kontaktu z urządzeniem. Praca przez CLI jest dozwolona tylko wtedy, gdy:

1. projekt ma stan `active`;
2. urządzenie ma stan `active`;
3. wpis `project_devices` ma stan `in_scope`;
4. istnieje aktywna i ważna autoryzacja dla tego projektu i urządzenia.

Nowe urządzenie ma stan `pending_authorization`. Gdy zakres jest niejasny,
zatrzymaj pracę fizyczną i potwierdź zakres z właścicielem. Nie zgaduj prawa
dostępu na podstawie adresu IP, nazwy hosta lub danych technicznych.

## Model danych

| Grupa | Tabele | Cel |
|---|---|---|
| Zakres | `projects`, `devices`, `project_devices`, `device_types`, `device_type_contracts` | Projekt, urządzenie, rola, typ i kontrakt danych typu. |
| Dostęp | `access_authorizations`, `access_authorization_operations`, `access_methods`, `active_authorized_devices` | Podstawa prawa, znormalizowane dozwolone operacje i techniczna ścieżka dostępu. |
| Informacje | `device_identifiers`, `device_information`, `device_interfaces`, `device_components` | Identyfikatory, fakty ze źródłem, porty i usługi. |
| Zależności | `device_relation_types`, `device_relations` | Kontrolowany słownik relacji, na przykład czujnik jest podłączony do Raspberry Pi. |
| Pomiar | `measurement_channels`, `measurement_samples`, `measurement_retention_runs` | Kanały liczbowe, jednostki, zakresy, próbki i audyt retencji. |
| RFID | `rfid_profiles`, `readers`, `elements`, `reads`, `sectors`, `blocks`, `artifacts`, `observations` | Osobne dane RFID połączone z wpisem w `devices`. |
| Audyt | `device_commands`, `device_scripts`, `device_command_runs`, `audit_output_retention_runs`, `clone_operations`, `operation_artifacts` | Nazwane polecenia i skrypty, ich metadane, retencja wyniku oraz audyt RFID. |
| Odzyskanie | `database_backups` i manifesty JSON | Zweryfikowane prywatne kopie SQLite oraz bezpieczne odtworzenie. |

`device_information` ma źródło, czas i poziom pewności. Baza zachowuje historię.
Tylko jeden wpis tego samego `property_key` może być bieżący. Identyfikatory RFID
i dane dostępu są oznaczone jako `sensitive` albo `critical`.

Aktywna autoryzacja dla czytnika, karty, taga lub breloka RFID wymaga wcześniej
zapisanego `rfid_profile`. Ta kontrola gwarantuje, że urządzenie RFID ma osobne
dane techniczne połączone z wpisem ogólnym.

Kontrakt typu może mieć tryb `strict` albo `advisory`. W trybie `strict` CLI
sprawdza klucze informacji, typ JSON, jednostkę i kanały pomiarowe. Standardowy
typ `sensor.temperature` ma kontrakt dla kanału `temperature.c` w `degC`.

Retencja pomiarów ma tryb podglądu. Usunięcie wymaga `--apply --confirm` i
tworzy wpis audytu. Retencja wyniku poleceń działa tak samo; usuwa tylko treść
wyjścia i zachowuje jego pierwotny hash SHA-256.

## Raspberry Pi

Baza zawiera wpis `computer:raspberry-pi-3` w projekcie
`home-infrastructure`. Wpis pochodzi z `../Raspberry/AGENTS.md`. Zawiera model,
interfejs SSH, odcisk klucza hosta i udokumentowane usługi. Nie jest to wynik
bieżącego połączenia z Raspberry Pi.

Urządzenie musi mieć stan `in_scope` i aktywną autoryzację dla wybranej
operacji. CLI nie może użyć SSH bez obu warunków. Baza nie przechowuje hasła
SSH ani prywatnego klucza.

Wpis `raspberry.credentials.sync` jest zarejestrowanym skryptem wrażliwym.
Uruchom go tylko przez `device-script-run` po aktywnej autoryzacji z operacją
`administer`. Audyt nie zapisuje jego wyjścia.

## Przykład: nowy czujnik temperatury

```bash
./rfid_vault.py device-add \
  --project home-infrastructure \
  --key sensor:temperature-salon \
  --name "Salon temperature sensor" \
  --kind embedded_device \
  --type sensor.temperature \
  --role support \
  --ownership household_owned

./rfid_vault.py device-relation-add \
  --source-device sensor:temperature-salon \
  --target-device computer:raspberry-pi-3 \
  --type connected_to \
  --source "owner-record:temperature-salon"

./rfid_vault.py measurement-channel-add \
  --device sensor:temperature-salon \
  --key temperature.c \
  --name Temperature \
  --quantity temperature \
  --unit degC \
  --minimum -40 \
  --maximum 125 \
  --retention-days 365 \
  --source "sensor-datasheet"
```

Dodaj próbkę tylko z podanym źródłem i czasem. Prawidłowa próbka poza
zadeklarowanym zakresem jest blokowana. Jeżeli urządzenie podało zły wynik,
zapisz go z `--quality invalid`.

## Ochrona danych

Plik bazy ma tryb `0600`. Katalog `vault` ma tryb `0700`. Nie dodawaj bazy,
artefaktów ani kopii do Git.

`database-backup` zapisuje kopię i manifest z SHA-256. `database-restore`
wymaga `--confirm`, najpierw tworzy kopię ochronną, a potem odtwarza tylko
kopię z prawidłowym manifestem i `integrity_check` SQLite.

Nie zapisuj hasła, tokenu ani klucza prywatnego jako informacji urządzenia.
Użyj `--secret-reference` w `access-method-set`, aby wskazać zewnętrzny magazyn
sekretów. CLI ukrywa takie referencje oraz identyfikatory oznaczone jako wrażliwe.

## Kontrola

```bash
./rfid_vault.py init
./rfid_vault.py verify
./rfid_vault.py projects
./rfid_vault.py devices --project home-infrastructure
./rfid_vault.py device-show --device computer:raspberry-pi-3
python3 -m unittest -v
```

Test `RFIDVaultCLIEndToEndTests` wykonuje wszystkie polecenia CLI na osobnej
bazie z symulowanym klientem Proxmark3. Nie zapisuje danych w bazie głównej i
nie kontaktuje Raspberry Pi.
