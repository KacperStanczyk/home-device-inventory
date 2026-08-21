# Home Device Inventory

Local inventory and audited CLI for authorized home devices and protected RFID
records. The CLI uses a deny-by-default authorization model. A device record
does not give permission to contact a device.

This repository is public. It contains source code and documentation. It does
not contain the local inventory database, device backups, artifacts, firmware
images, passwords, tokens, or private keys.

## Quick start

Use Python 3 with the standard `sqlite3` module.

```bash
git clone https://github.com/KacperStanczyk/home-device-inventory.git
cd home-device-inventory
./rfid_vault.py --help
```

Create or migrate a local database only on a trusted local computer:

```bash
./rfid_vault.py init
./rfid_vault.py verify
```

The default database is `vault/rfid_inventory.sqlite3`. The complete `vault/`
directory is ignored by Git. Do not copy it into an issue, a pull request, or
the repository.

## Device requirements

The core CLI needs only Python. A device operation needs its own local tools:

- Proxmark3: a compatible `pm3` client and local port access.
- Raspberry Pi: `ssh` with strict host-key checking.
- Gree Wi-Fi: Linux NetworkManager tools `nmcli` and `zenity`.
- Zigbee diagnostics: `udevadm`; `setfacl` is optional for port repair.

The source does not include Proxmark3 worktrees. Use the upstream
`RfidResearchGroup/proxmark3` release required by the inventory, or install a
compatible `pm3` client. The local workspace currently uses the upstream tag
`v4.20728` for its matching firmware instructions.

Some Raspberry Pi operations can use an authorized local sibling workspace at
`../Raspberry`. It is not part of this repository. Never add a script that
reads credentials, a local database, a backup, or a firmware image to Git.
Without this workspace, `init` still creates a local database. It does not
register the private credential inventory script.

## Safe operation

Use `./rfid_vault.py` for each repeatable device action. Before Proxmark3 work,
run `./rfid_vault.py pm3-probe`. Use named commands with
`./rfid_vault.py pm3-run COMMAND_KEY`.

Read [CLI.md](CLI.md) for command examples. Read [PROJECT.md](PROJECT.md) for
the data model and safety rules. [AGENTS.md](AGENTS.md) defines the required
maintenance procedure.

## Verification

```bash
python3 -m unittest -v
./rfid_vault.py verify
```

The test suite uses a temporary database and a simulated Proxmark3 client. It
does not contact a physical device. A physical-device operation still requires
an active project, device, authorization, and local access path.

Tests for private Raspberry scripts run only when the authorized
`../Raspberry` workspace is present. In a source-only clone, these tests are
skipped.
