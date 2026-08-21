#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${DEVICE_CLI_CONTEXT:-}" != "1" || "${DEVICE_CLI_SCRIPT_KEY:-}" != "raspberry.stress.test" ]]; then
    printf 'Błąd: uruchom skrypt przez ./rfid_vault.py device-script-run raspberry.stress.test.\n' >&2
    exit 2
fi

RASPBERRY_HOST="${RASPBERRY_HOST:-${DEVICE_CLI_DEVICE_ADDRESS:-raspberry.example.invalid}}"
RASPBERRY_USER="${RASPBERRY_USER:-inventory-user}"
SSH_OPTIONS=(
    -o BatchMode=yes
    -o ConnectTimeout=15
    -o StrictHostKeyChecking=yes
    -o PasswordAuthentication=no
    -o KbdInteractiveAuthentication=no
    -o PreferredAuthentications=publickey
    -o LogLevel=ERROR
)

exec ssh "${SSH_OPTIONS[@]}" "${RASPBERRY_USER}@${RASPBERRY_HOST}" 'bash -s' <<'REMOTE'
set -Eeuo pipefail
export LC_ALL=C

LOAD_SECONDS=300
THERMAL_LIMIT_C=76.0
MONITOR_INTERVAL_SECONDS=1
STORAGE_MIB=128
sample_count=0
current_fault_samples=0
max_temperature_c=0
load_pid=''
temporary_directory=''
load_status=0
abort_reason='none'

cleanup() {
    local status=$?
    trap - EXIT INT TERM HUP
    if [[ -n "${load_pid}" ]] && kill -0 "${load_pid}" 2>/dev/null; then
        kill -TERM "${load_pid}" 2>/dev/null || true
        wait "${load_pid}" 2>/dev/null || true
    fi
    if [[ -n "${temporary_directory}" && -d "${temporary_directory}" ]]; then
        rm -f -- "${temporary_directory}/io-test.bin"
        rmdir -- "${temporary_directory}" 2>/dev/null || true
    fi
    exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

throttle_value() {
    local line hex
    line="$(vcgencmd get_throttled)"
    hex="${line#throttled=0x}"
    printf '%s' "$((16#${hex}))"
}

temperature_value() {
    local line value
    line="$(vcgencmd measure_temp)"
    value="${line#temp=}"
    value="${value//[!0-9.]/}"
    printf '%s' "${value}"
}

sample_health() {
    local phase="$1" throttle temperature arm_clock current_bits
    throttle="$(throttle_value)"
    temperature="$(temperature_value)"
    arm_clock="$(vcgencmd measure_clock arm | cut -d= -f2)"
    current_bits=$((throttle & 0xF))
    sample_count=$((sample_count + 1))
    if (( current_bits != 0 )); then
        current_fault_samples=$((current_fault_samples + 1))
    fi
    if awk "BEGIN { exit !(${temperature} > ${max_temperature_c}) }"; then
        max_temperature_c="${temperature}"
    fi
    printf 'SAMPLE phase=%s number=%s throttle=0x%x current_bits=0x%x temperature_c=%s arm_clock_hz=%s\n' \
        "${phase}" "${sample_count}" "${throttle}" "${current_bits}" "${temperature}" "${arm_clock}"
    if awk "BEGIN { exit !(${temperature} >= ${THERMAL_LIMIT_C}) }"; then
        abort_reason='thermal_safety_limit'
        return 1
    fi
    if (( current_bits & 0x1 )); then
        abort_reason='current_undervoltage'
        return 1
    fi
    if (( current_bits != 0 )); then
        abort_reason='current_throttle_flag'
        return 1
    fi
    return 0
}

service_health() {
    systemctl is-active --quiet ssh
    systemctl is-active --quiet docker
    systemctl is-active --quiet unbound
    test -z "$(systemctl --failed --no-legend --plain)"
    curl --fail --silent --show-error --max-time 15 --output /dev/null 'http://127.0.0.1:8080/admin/'
    curl --fail --silent --show-error --max-time 15 --output /dev/null 'http://127.0.0.1:3001/'
    curl --fail --silent --show-error --max-time 15 --output /dev/null 'http://127.0.0.1:8765/api/healthcheck'
    if ss -ltnH 'sport = :8090' | grep -q .; then
        curl --fail --silent --show-error --max-time 15 --output /dev/null 'http://127.0.0.1:8090/healthz'
    fi
}

initial_throttle="$(throttle_value)"
printf 'INFO host=%s time=%s kernel=%s cpu_count=%s\n' \
    "$(hostname)" "$(date --iso-8601=seconds)" "$(uname -r)" "$(nproc)"
printf 'INFO load_seconds=%s thermal_limit_c=%s monitor_interval_s=%s storage_mib=%s\n' \
    "${LOAD_SECONDS}" "${THERMAL_LIMIT_C}" "${MONITOR_INTERVAL_SECONDS}" "${STORAGE_MIB}"
sample_health baseline

temporary_directory="$(mktemp -d "${HOME}/.raspberry-stress.XXXXXX")"
storage_source="$(findmnt -n -o SOURCE --target "${temporary_directory}")"
storage_fstype="$(findmnt -n -o FSTYPE --target "${temporary_directory}")"
if [[ "${storage_fstype}" == 'tmpfs' ]]; then
    printf 'FAIL storage test target is tmpfs, not persistent storage\n' >&2
    exit 1
fi
printf 'INFO storage_target_source=%s storage_target_fstype=%s\n' "${storage_source}" "${storage_fstype}"
storage_file="${temporary_directory}/io-test.bin"
write_result="$(dd if=/dev/zero of="${storage_file}" bs=1M count="${STORAGE_MIB}" conv=fdatasync 2>&1 >/dev/null)"
stored_hash="$(sha256sum "${storage_file}" | awk '{print $1}')"
read_hash="$(dd if="${storage_file}" bs=1M status=none | sha256sum | awk '{print $1}')"
if [[ "${stored_hash}" != "${read_hash}" ]]; then
    printf 'FAIL storage readback hash mismatch\n' >&2
    exit 1
fi
printf 'PASS storage write and readback verified | %s\n' "$(printf '%s' "${write_result}" | tail -n 1)"
rm -f -- "${storage_file}"
rmdir -- "${temporary_directory}"
temporary_directory=''
sample_health after_storage

default_gateway="$(ip -4 route show default | awk 'NR == 1 {print $3}')"
if [[ -z "${default_gateway}" ]]; then
    printf 'FAIL no IPv4 default gateway\n' >&2
    exit 1
fi
ping -c 20 -W 2 "${default_gateway}" >/dev/null
getent ahostsv4 example.com >/dev/null
curl --fail --silent --show-error --max-time 20 --output /dev/null 'https://example.com/'
printf 'PASS network gateway, DNS, and HTTPS checks\n'
sample_health after_network

cpu_workers="$(nproc)"
available_mib="$(awk '/MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo)"
memory_mib=$((available_mib / 4))
(( memory_mib > 256 )) && memory_mib=256
(( memory_mib < 64 )) && memory_mib=64

if command -v stress-ng >/dev/null 2>&1; then
    load_engine='stress-ng'
    stress-ng --cpu "${cpu_workers}" --cpu-method all \
        --vm 1 --vm-bytes "${memory_mib}M" --vm-keep --verify \
        --timeout "${LOAD_SECONDS}s" --metrics-brief &
    load_pid=$!
else
    load_engine='python-multiprocessing'
    python3 - "${LOAD_SECONDS}" "${cpu_workers}" "${memory_mib}" <<'PY' &
import hashlib
import multiprocessing as mp
import os
import signal
import sys
import time

duration = int(sys.argv[1])
cpu_workers = int(sys.argv[2])
memory_mib = int(sys.argv[3])
stop = mp.Event()


def cpu_worker() -> None:
    block = os.urandom(1024 * 1024)
    while not stop.is_set():
        hashlib.sha256(block).digest()


def memory_worker() -> None:
    block = bytearray(memory_mib * 1024 * 1024)
    while not stop.is_set():
        for offset in range(0, len(block), 4096):
            block[offset] = (block[offset] + 1) & 0xFF


workers = [mp.Process(target=cpu_worker) for _ in range(cpu_workers)]
workers.append(mp.Process(target=memory_worker))
for worker in workers:
    worker.start()


def request_stop(_signum: int, _frame: object) -> None:
    stop.set()


signal.signal(signal.SIGTERM, request_stop)
signal.signal(signal.SIGINT, request_stop)
deadline = time.monotonic() + duration
try:
    while time.monotonic() < deadline and not stop.is_set():
        if any(not worker.is_alive() for worker in workers):
            raise RuntimeError("load worker stopped early")
        time.sleep(0.5)
finally:
    stop.set()
    for worker in workers:
        worker.join(5)
    for worker in workers:
        if worker.is_alive():
            worker.terminate()
    for worker in workers:
        worker.join(5)
PY
    load_pid=$!
fi

printf 'INFO load_engine=%s cpu_workers=%s memory_mib=%s\n' \
    "${load_engine}" "${cpu_workers}" "${memory_mib}"

load_started="$(date +%s)"
while kill -0 "${load_pid}" 2>/dev/null; do
    if ! sample_health load; then
        kill -TERM "${load_pid}" 2>/dev/null || true
        wait "${load_pid}" 2>/dev/null || true
        load_pid=''
        load_status=1
        break
    fi
    sleep "${MONITOR_INTERVAL_SECONDS}"
done
if [[ -n "${load_pid}" ]]; then
    if wait "${load_pid}"; then
        load_status=0
    else
        load_status=$?
    fi
    load_pid=''
fi
load_elapsed=$(( $(date +%s) - load_started ))

sleep 5
final_throttle="$(throttle_value)"
new_throttle_bits=$((final_throttle & ~initial_throttle))
sample_health recovery || true

if service_health; then
    services_status='pass'
    printf 'PASS services remained healthy after load\n'
else
    services_status='fail'
    printf 'FAIL one or more services are unhealthy after load\n' >&2
fi

power_new_bits=$((new_throttle_bits & 0x10001))
thermal_new_bits=$((new_throttle_bits & 0xE000E))
printf 'SUMMARY load_status=%s abort_reason=%s load_elapsed_s=%s max_temperature_c=%s samples=%s current_fault_samples=%s initial_throttle=0x%x final_throttle=0x%x new_throttle_bits=0x%x new_power_bits=0x%x new_thermal_bits=0x%x services=%s\n' \
    "${load_status}" "${abort_reason}" "${load_elapsed}" "${max_temperature_c}" "${sample_count}" \
    "${current_fault_samples}" "${initial_throttle}" "${final_throttle}" "${new_throttle_bits}" \
    "${power_new_bits}" "${thermal_new_bits}" "${services_status}"

if (( load_status != 0 || current_fault_samples != 0 || new_throttle_bits != 0 )) || \
   [[ "${abort_reason}" != 'none' || "${services_status}" != 'pass' ]]; then
    printf 'FAIL controlled Raspberry Pi stress test did not meet all limits\n' >&2
    exit 1
fi

printf 'PASS controlled Raspberry Pi stress test met all limits\n'
REMOTE
