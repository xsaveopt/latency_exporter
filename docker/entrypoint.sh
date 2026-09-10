#!/usr/bin/env bash
set -euo pipefail

APP=latency_exporter

CONFIG_FILE="${LATENCY_EXPORTER_CONFIG:-/config/config.yml}"
LISTEN_ADDR="${LATENCY_EXPORTER_ADDR:-:9428}"
PORTS_INTERNAL="${LISTEN_ADDR##*:}"
EXEC_MOUNTS=""
REQUIRED_RW=""
ENV_REPORT="LATENCY_EXPORTER_CONFIG LATENCY_EXPORTER_ADDR LATENCY_EXPORTER_PATH LATENCY_EXPORTER_LOG_LEVEL TZ"
ENV_SECRET=""
NET_DNS_TARGET="cloudflare.com"
NET_TCP_TARGET="1.1.1.1:443"

UID_IN=$(id -u)
GID_IN=$(id -g)

C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
[ -t 1 ] || { C_RED=; C_YEL=; C_GRN=; C_DIM=; C_RST=; }

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log()  { printf '%s [%s] %s%s%s %s\n' "$(ts)" "$APP" "$2" "$1" "$C_RST" "$3"; }
info() { log INFO  "$C_GRN" "$*"; }
warn() { log WARN  "$C_YEL" "$*"; }
err()  { log ERROR "$C_RED" "$*"; }
note() { printf '%s %s[%s]      %s%s\n' "$(ts)" "$C_DIM" "$APP" "$*" "$C_RST"; }

FATAL=0
fail() { err "$*"; FATAL=1; }

map_host_id() {
  local want="$1" mapfile="$2"
  awk -v w="$want" '{ if (w>=$1 && w<$1+$3) { print $2+(w-$1); f=1; exit } } END { if(!f) print "?" }' "$mapfile" 2>/dev/null || echo '?'
}

USERNS=0
HOST_UID="${UID_IN}"
HOST_GID="${GID_IN}"
if [ -r /proc/self/uid_map ]; then
  read -r u0 h0 _ < /proc/self/uid_map
  if [ "${u0:-0}" != "0" ] || [ "${h0:-0}" != "0" ]; then
    USERNS=1
    HOST_UID=$(map_host_id "${UID_IN}" /proc/self/uid_map)
    HOST_GID=$(map_host_id "${GID_IN}" /proc/self/gid_map)
  fi
fi

mount_opt() {
  awk -v p="$1" -v o="$2" '$5==p { n=split($6,a,","); for(i=1;i<=n;i++) if(a[i]==o){print o; exit} }' /proc/self/mountinfo 2>/dev/null
}

is_system_fs() {
  case "$1" in
    proc|sysfs|cgroup|cgroup2|devpts|mqueue|tmpfs|overlay|devtmpfs|securityfs|bpf|tracefs|debugfs|fusectl|configfs|pstore|autofs|binfmt_misc|hugetlbfs|nsfs|fuse.lxcfs|ramfs|rpc_pipefs) return 0 ;;
  esac
  return 1
}

is_system_path() {
  case "$1" in
    /|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/etc/hostname|/etc/hosts|/etc/resolv.conf) return 0 ;;
  esac
  return 1
}

is_required_rw() {
  case " ${REQUIRED_RW} " in *" $1 "*) return 0 ;; esac
  return 1
}

check_rw() {
  local dir="$1" label="$2" required=0
  is_required_rw "$dir" && required=1
  if [ ! -d "$dir" ]; then
    if [ "$required" = "1" ]; then fail "${label}: ${dir} is not present"; else warn "${label}: ${dir} is not present"; fi
    return 0
  fi
  local owner mode probe ro=
  owner=$(stat -c '%U:%G (%u:%g)' "$dir" 2>/dev/null || echo '?')
  mode=$(stat -c '%a' "$dir" 2>/dev/null || echo '?')
  [ "$(mount_opt "$dir" ro)" = ro ] && ro=' [mounted read-only]'
  probe="${dir}/.${APP}-write-test.${RANDOM}"
  if [ -r "$dir" ] && touch "$probe" 2>/dev/null; then
    rm -f "$probe"
    info "${label}: read/write OK (${dir})"
    return 0
  fi
  if [ "$required" = "1" ]; then
    fail "${label}: cannot read+write ${dir} as uid=${UID_IN}"
  elif [ -n "$ro" ]; then
    note "${label}: ${dir} is read-only${ro}; skipping (fine if you mounted it ro on purpose)"
    return 0
  else
    warn "${label}: ${dir} is not writable by uid=${UID_IN}"
  fi
  note "current owner=${owner} mode=${mode}${ro}"
  if [ "${USERNS}" = "1" ]; then
    note "fix on host: chown -R ${HOST_UID}:${HOST_GID} <host-path-mounted-at-${dir}>"
  else
    note "fix on host: chown -R ${UID_IN}:${GID_IN} <host-path-mounted-at-${dir}>"
  fi
}

check_perms() {
  local dir="$1" mode others
  [ -d "$dir" ] || return 0
  mode=$(stat -c '%a' "$dir" 2>/dev/null || echo '')
  [ -z "$mode" ] && return 0
  others="${mode: -1}"
  case "$others" in
    2|3|6|7) warn "loose permissions on ${dir} (mode ${mode}, writable by any user); tighten to 0750/0770 unless this is intentional" ;;
  esac
}

check_flags() {
  local dir="$1"
  if [ "$(mount_opt "$dir" noexec)" = noexec ]; then
    case " ${EXEC_MOUNTS} " in
      *" ${dir} "*) warn "${dir} is mounted noexec but this app must execute files there; remove noexec from that mount" ;;
    esac
  fi
}

check_caps() {
  local hex val
  hex=$(awk '/^CapEff:/{print $2; exit}' /proc/self/status 2>/dev/null || echo '')
  if [ -z "$hex" ]; then note "capabilities: could not read /proc/self/status"; return 0; fi
  val=$((16#$hex))
  if [ "$val" -eq 0 ]; then note "capabilities: all dropped (CapEff=${hex}); good"; return 0; fi
  local names="0:chown 1:dac_override 2:dac_read_search 3:fowner 4:fsetid 5:kill 6:setgid 7:setuid 8:setpcap 9:linux_immutable 10:net_bind_service 11:net_broadcast 12:net_admin 13:net_raw 14:ipc_lock 16:sys_module 17:sys_rawio 18:sys_chroot 19:sys_ptrace 21:sys_admin 22:sys_boot 24:sys_resource 25:sys_time 27:mknod 29:audit_write 31:setfcap 38:perfmon 39:bpf"
  local default=" 0 1 3 4 5 6 7 8 10 13 18 27 29 31 "
  local extra='' base='' e bit name
  for e in $names; do
    bit="${e%%:*}"; name="${e#*:}"
    if (( (val >> bit) & 1 )); then
      case "$default" in *" $bit "*) base="${base} ${name}" ;; *) extra="${extra} ${name}" ;; esac
    fi
  done
  if [ -n "$extra" ]; then
    warn "elevated capabilities present beyond the docker default:${extra}"
    note "this exporter needs no capabilities at all; drop them (cap_drop: [ALL])"
  else
    note "capabilities: docker default set only (${base# }); this exporter needs none, cap_drop: [ALL] is safe"
  fi
}

check_clock() {
  local year
  year=$(date -u +%Y 2>/dev/null || echo 0)
  if [ "${year:-0}" -lt 2024 ]; then
    warn "system clock looks wrong (UTC year=${year}); TLS, tokens and scheduling may misbehave"
  fi
  if [ -z "${TZ:-}" ] && [ ! -e /etc/localtime ]; then
    note "timezone not configured (TZ unset, no /etc/localtime); timestamps will be UTC"
  fi
}

is_secret() {
  case " ${ENV_SECRET} " in *" $1 "*) return 0 ;; esac
  return 1
}

report_env() {
  [ -n "${ENV_REPORT}" ] || return 0
  note "configuration (environment overrides; blank means default):"
  local v val shown
  for v in ${ENV_REPORT}; do
    val="${!v:-}"
    if [ -z "$val" ]; then
      shown='- (unset)'
    elif is_secret "$v"; then
      shown='****** (set)'
    else
      shown="$val"
    fi
    printf '%s %s[%s]        %-28s %s%s\n' "$(ts)" "$C_DIM" "$APP" "$v" "$shown" "$C_RST"
  done
}

check_config() {
  if [ -d "$CONFIG_FILE" ]; then
    fail "config ${CONFIG_FILE} is a directory, not a file"
    note "docker creates a directory when the host file did not exist at mount time; create the file on the host, remove the stray directory and restart"
    return 0
  fi
  if [ ! -e "$CONFIG_FILE" ]; then
    fail "config ${CONFIG_FILE} does not exist"
    note "mount your target file there, e.g. ./config.yml:/config/config.yml:ro, or point LATENCY_EXPORTER_CONFIG at it"
    return 0
  fi
  if [ ! -r "$CONFIG_FILE" ]; then
    fail "config ${CONFIG_FILE} is not readable by uid=${UID_IN}"
    note "current owner=$(stat -c '%U:%G (%u:%g)' "$CONFIG_FILE" 2>/dev/null || echo '?') mode=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || echo '?')"
    note "fix on host: chmod 0644 <host-path-of-config>, or chown it to ${HOST_UID}:${HOST_GID}"
    return 0
  fi
  info "config ${CONFIG_FILE} is readable"
}

check_ping() {
  grep -Eq '^[[:space:]]*(-[[:space:]]*)?type:[[:space:]]*["'\'']?icmp' "$CONFIG_FILE" 2>/dev/null || return 0
  local range=/proc/sys/net/ipv4/ping_group_range lo hi
  if [ ! -r "$range" ]; then
    note "icmp: ${range} is not exposed by this kernel or sandbox; unprivileged ping sockets are decided by the runtime"
    return 0
  fi
  read -r lo hi < "$range" || return 0
  if [ "${GID_IN}" -ge "${lo:-1}" ] && [ "${GID_IN}" -le "${hi:-0}" ]; then
    info "icmp: unprivileged ping sockets allowed for gid=${GID_IN} (ping_group_range ${lo} ${hi})"
    return 0
  fi
  warn "icmp: gid=${GID_IN} is outside net.ipv4.ping_group_range (${lo} ${hi}); icmp targets will fail with reason=permission"
  note "fix in compose: sysctls: { net.ipv4.ping_group_range: \"0 2147483647\" }, or docker run --sysctl net.ipv4.ping_group_range=\"0 2147483647\""
}

listening_ports() {
  awk '$4=="0A"{n=split($2,a,":"); print a[2]}' /proc/net/tcp /proc/net/tcp6 2>/dev/null \
    | while read -r h; do [ -n "$h" ] && printf '%d\n' "0x$h"; done | sort -un
}

check_ports() {
  [ -n "${PORTS_INTERNAL}" ] || return 0
  local held p
  held=$(listening_ports)
  for p in ${PORTS_INTERNAL}; do
    if printf '%s\n' "$held" | grep -qx "$p"; then
      warn "port ${p} is already in use before services start; a service may fail to bind"
      note "this usually means network_mode: host with another process on ${p}; remap or stop the conflict"
    fi
  done
}

check_net() {
  [ "${PREFLIGHT_NET_CHECK:-0}" = "1" ] || return 0
  local host="${NET_TCP_TARGET%:*}" port="${NET_TCP_TARGET##*:}"
  if getent hosts "${NET_DNS_TARGET}" >/dev/null 2>&1; then
    info "outbound DNS OK (resolved ${NET_DNS_TARGET})"
  else
    warn "outbound DNS failed (could not resolve ${NET_DNS_TARGET}); name resolution may be broken"
  fi
  if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
    info "outbound TCP OK (connected ${host}:${port})"
  else
    warn "outbound TCP to ${host}:${port} failed; egress may be blocked"
  fi
}

collect_mounts() {
  declare -A seen
  MOUNTS=()
  local mp fstype d
  for d in ${REQUIRED_RW}; do
    [ -n "${seen[$d]:-}" ] && continue
    seen["$d"]=1
    MOUNTS+=("$d")
  done
  while IFS=$'\t' read -r mp fstype; do
    [ -z "$mp" ] && continue
    [ -n "${seen[$mp]:-}" ] && continue
    is_system_fs "$fstype" && continue
    is_system_path "$mp" && continue
    [ -d "$mp" ] || continue
    seen["$mp"]=1
    MOUNTS+=("$mp")
  done < <(awk '{ s=0; for(i=1;i<=NF;i++) if($i=="-"){s=i;break} if(s) print $5 "\t" $(s+1) }' /proc/self/mountinfo 2>/dev/null)
}

info "starting preflight checks"
if [ "${UID_IN}" = "0" ]; then
  warn "running as uid=0 (root); this image is built to run unprivileged"
else
  note "all processes run as uid=${UID_IN} gid=${GID_IN} (non-root)"
fi
if [ "${USERNS}" = "1" ]; then
  warn "user namespace remapping is active (rootless docker or userns-remap)"
  note "inside uid=${UID_IN} maps to HOST uid=${HOST_UID}; inside gid=${GID_IN} maps to HOST gid=${HOST_GID}"
  note "when fixing bind-mount ownership on the host, chown to the HOST ids above, not ${UID_IN}:${GID_IN}"
fi

check_caps
check_clock
report_env
check_config

collect_mounts
for m in "${MOUNTS[@]}"; do
  if is_required_rw "$m"; then label="required volume ${m}"; else label="bind mount ${m}"; fi
  check_rw "$m" "$label"
  check_perms "$m"
  check_flags "$m"
done

if [ "${FATAL}" = "1" ]; then
  err "preflight failed; refusing to start"
  note "fix the problems shown above on the host, then restart the container"
  exit 1
fi

check_ping
check_ports
check_net

info "preflight complete; launching ${APP}"
exec /usr/local/bin/latency_exporter "$@"
