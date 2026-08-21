# Instrukcje pracy w projekcie Home Device Inventory

Stosuj ASD-STE100 Simplified Technical English po polsku albo po angielsku.

## Zakres

- Projekt służy do nauki, celów edukacyjnych, rozwoju zawodowego i prac w prywatnym domu użytkownika.
- Użytkownik oświadcza, że jest profesjonalistą i ma pełną autoryzację do urządzeń zapisanych jako aktywne w tym projekcie.
- SQLite w `vault/rfid_inventory.sqlite3` jest wspólnym rejestrem projektów, urządzeń, dostępów, pomiarów, poleceń i audytu.
- Jeśli zakres nowego urządzenia jest niejasny, zapisz je jako `pending_authorization` i zadaj jedno konkretne pytanie. Nie zgaduj.
- Rejestracja, opis i zapis pomiaru nie dają prawa do połączenia z urządzeniem. Przed połączeniem sprawdź aktywny projekt, urządzenie i autoryzację.
- Zapisuj źródło, czas i poziom pewności każdej nowej informacji urządzenia. Nie wpisuj haseł, tokenów ani kluczy prywatnych.

## Zasada nadrzędna CLI

1. `./rfid_vault.py` jest jedynym normalnym punktem uruchomienia każdej powtarzalnej operacji urządzenia.
2. Przed nowym skryptem sprawdź istniejące polecenie CLI. Jeśli go nie ma, rozbuduj CLI i zarejestruj skrypt przez `device-script-add` albo dodaj polecenie wbudowane. Po zmianie treści zarejestrowanego skryptu uruchom `device-script-add` ponownie; hash i rewizja muszą się zmienić po przeglądzie.
3. Skrypt urządzenia ma działać tylko z `device-script-run`. Ma odrzucić brak `DEVICE_CLI_CONTEXT` i `DEVICE_CLI_SCRIPT_KEY`, oraz używać listy argumentów procesu. Nie używaj `shell=True` ani surowego SSH, curl, portu szeregowego lub klienta Proxmark3 jako zwykłej ścieżki.
4. CLI musi przed połączeniem sprawdzić projekt, urządzenie i autoryzację. Musi zapisać wynik także dla blokady, błędu i limitu czasu. Nie zapisuj wyniku skryptu, gdy może zawierać sekret.
5. Gdy operacja jest potrzebna drugi raz albo ma błąd, napraw CLI, rejestr, dokumentację i test regresji. Nie dodawaj drugiego ręcznego obejścia.

## Obowiązkowy sposób użycia urządzenia

1. Użyj `./rfid_vault.py pm3-probe` przed pracą z Proxmark3.
2. Użyj nazwanego polecenia przez `./rfid_vault.py pm3-run COMMAND_KEY`.
3. Nie uruchamiaj surowego klienta Proxmark3 jako normalnej ścieżki pracy.
4. Surowego klienta użyj tylko do diagnostyki CLI albo do poznania nowej operacji.
5. Po udanym użyciu nowej operacji dodaj ją do CLI przez `pm3-command-add` albo jako polecenie wbudowane.
6. Dodaj opis polecenia, wymagane uprawnienie, poziom ryzyka, limit czasu i test regresji.

## Rozbudowa CLI

- Jeśli operacja może się powtórzyć, dodaj ją do CLI. Nie zostawiaj jej tylko jako polecenia w notatce lub historii terminala.
- Zachowaj zgodność istniejących nazw poleceń, gdy jest to możliwe.
- Polecenie urządzenia musi używać listy argumentów procesu. Nie używaj `shell=True`.
- Polecenie musi sprawdzić aktywny projekt, urządzenie i autoryzację przed połączeniem.
- Domyślnie wybierz wersję klienta zapisaną w `readers.client_version`. Nie aktualizuj firmware tylko po to, aby dopasować przypadkowo nowszy klient.
- Zapisz wynik wykonania w `device_command_runs`, także gdy wykonanie jest zablokowane lub kończy się błędem.
- Nie zapisuj haseł, tokenów ani prywatnych kluczy w kodzie, argumentach lub tabeli `access_methods`.
- Dla urządzenia ogólnego użyj `device-add`, typu w `device_types`, informacji ze źródłem, interfejsu i relacji. Dla czujnika dodaj kanał pomiaru przed pierwszą próbką.
- Przed użyciem nowego terminu relacji dodaj go przez `relation-type-add`. Dla powtarzalnego typu czujnika zapisz kontrakt przez `device-type-contract-set`.
- Retencję pomiaru i wyniku audytu najpierw uruchom w trybie podglądu. Usunięcie wymaga `--apply --confirm` i musi mieć wpis audytu.
- Przed zmianą schematu lub odtworzeniem użyj `database-backup`. Odtworzenie wykonaj tylko przez `database-restore --confirm`; CLI utworzy kopię ochronną.
- Dane RFID zapisuj w `rfid_profiles` i istniejących tabelach odczytów. Nie mieszaj kluczy sektorów z ogólnymi informacjami urządzenia.

## Naprawa problemów

- Gdy pojawi się problem obsługi, najpierw go odtwórz i zapisz dokładny objaw.
- Napraw przyczynę w `rfid_vault.py`, `rfid_device.py` lub schemacie SQLite.
- Dodaj test, który nie przechodził przed naprawą i przechodzi po naprawie.
- Dodaj do `pm3-probe` jasną diagnozę i jedną wykonalną naprawę, jeśli problem może się powtórzyć.
- Nie kończ pracy na ręcznym obejściu, jeśli CLI może wykryć albo naprawić problem.
- Po zmianie uruchom `python3 -m unittest -v`, `./rfid_vault.py verify` i odpowiednie polecenie na rzeczywistym urządzeniu.
