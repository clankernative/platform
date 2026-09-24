#!/bin/bash
# Runs as root on every boot (GCE startup-script). Installs the native Docker
# engine and build prerequisites once, then writes a host report that says
# whether this kernel can run day2's Linux qualification at all.
set -euo pipefail

state_dir=/var/lib/day2-qualification
marker="$state_dir/provisioned-v1"
report="$state_dir/host-report.txt"
install -d -m 0755 "$state_dir"

if [[ ! -f "$marker" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # build-essential/pkg-config: host build of xtask (bundled SQLite, ring).
  # curl/tar: xtask bootstrap fetches the pinned Roc compiler with /usr/bin/curl
  # and /usr/bin/tar. rsync/git/jq/xz-utils: moving and inspecting the workspace.
  apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg tar xz-utils git rsync jq build-essential pkg-config

  # Docker Engine from Docker's own Debian repository (not docker.io), so the
  # engine supports --cgroupns=private and current BuildKit.
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  touch "$marker"
fi

systemctl start docker

check() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'PASS %s\n' "$label"
  else
    printf 'FAIL %s\n' "$label"
  fi
}

kernel_at_least_6_2() {
  local major minor
  IFS=. read -r major minor _ <<<"$(uname -r)"
  ((major > 6 || (major == 6 && minor >= 2)))
}

{
  printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'uname: %s\n' "$(uname -srm)"
  printf 'lsm: %s\n' "$(cat /sys/kernel/security/lsm 2>/dev/null || echo unavailable)"
  printf 'cgroup fs: %s\n' "$(stat -fc %T /sys/fs/cgroup)"
  printf 'docker: %s\n' "$(docker info --format '{{.ServerVersion}} {{.OSType}}/{{.Architecture}} cgroup={{.CgroupVersion}} driver={{.CgroupDriver}} security={{json .SecurityOptions}}' 2>&1)"
  check "x86_64 machine" test "$(uname -m)" = x86_64
  check "kernel >= 6.2 (Landlock ABI 3)" kernel_at_least_6_2
  check "landlock in active LSM list" grep -qw landlock /sys/kernel/security/lsm
  check "seccomp filter support" grep -q '^Seccomp_filters:' /proc/self/status
  check "cgroup v2 unified hierarchy" test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs
  check "docker engine reports x86_64" test "$(docker info --format '{{.Architecture}}')" = x86_64
  check "docker private cgroupns" sh -c 'docker run --rm --cgroupns=private debian:stable-slim cat /proc/self/cgroup | grep -qx "0::/"'
} >"$report" 2>&1 || true

logger -t day2-qualification "host report written to $report"
