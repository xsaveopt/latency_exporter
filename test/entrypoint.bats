setup() {
  load helper
  CASE_DIR="$BATS_TEST_TMPDIR"
}

write_config() {
  CONFIG="$CASE_DIR/config.yml"
  printf '%s\n' "$@" > "$CONFIG"
}

@test "check_config accepts a readable file" {
  write_config "targets: []"
  case_body() {
    CONFIG_FILE="$CONFIG"
    check_config
    echo "FATAL=$FATAL"
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"config $CONFIG is readable"* ]] || return 1
  [[ $output == *"FATAL=0"* ]] || return 1
}

@test "check_config fails on a missing file" {
  case_body() {
    CONFIG_FILE="$CASE_DIR/missing.yml"
    check_config
    echo "FATAL=$FATAL"
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"config $CASE_DIR/missing.yml does not exist"* ]] || return 1
  [[ $output == *"point LATENCY_EXPORTER_CONFIG at it"* ]] || return 1
  [[ $output == *"FATAL=1"* ]] || return 1
}

@test "check_config fails on a directory left by a bind mount" {
  mkdir "$CASE_DIR/config.yml"
  case_body() {
    CONFIG_FILE="$CASE_DIR/config.yml"
    check_config
    echo "FATAL=$FATAL"
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"is a directory, not a file"* ]] || return 1
  [[ $output == *"FATAL=1"* ]] || return 1
}

@test "check_config fails on an unreadable file" {
  skip_as_root
  write_config "targets: []"
  chmod 000 "$CONFIG"
  case_body() {
    CONFIG_FILE="$CONFIG"
    check_config
    echo "FATAL=$FATAL"
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"config $CONFIG is not readable by uid=$(id -u)"* ]] || return 1
  [[ $output == *"mode=0"* ]] || return 1
  [[ $output == *"FATAL=1"* ]] || return 1
}

@test "check_ping stays quiet without icmp targets" {
  write_config "targets:" "  - name: ssh" "    type: tcp" "    address: 192.0.2.1:22"
  case_body() {
    CONFIG_FILE="$CONFIG"
    check_ping
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ] || return 1
}

@test "check_ping stays quiet on a missing config" {
  case_body() {
    CONFIG_FILE="$CASE_DIR/missing.yml"
    check_ping
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ] || return 1
}

@test "check_ping notices a lowercase icmp target" {
  write_config "targets:" "  - name: gateway" "    type: icmp" "    host: 192.0.2.1"
  case_body() {
    CONFIG_FILE="$CONFIG"
    check_ping
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"icmp: "* ]] || return 1
}

@test "check_ping notices a quoted icmp type on the list item line" {
  write_config "targets:" "  - type: 'icmp'" "    name: gateway" "    host: 192.0.2.1"
  case_body() {
    CONFIG_FILE="$CONFIG"
    check_ping
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"icmp: "* ]] || return 1
}

@test "check_ping notices an uppercase ICMP type" {
  write_config "targets:" "  - name: gateway" "    type: ICMP" "    host: 192.0.2.1"
  case_body() {
    CONFIG_FILE="$CONFIG"
    check_ping
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"icmp: "* ]] || return 1
}

@test "check_ping accepts a gid inside ping_group_range" {
  ping_range
  [ "$RANGE_LO" -le "$RANGE_HI" ] || skip "ping_group_range is empty here"
  write_config "targets:" "  - name: gateway" "    type: icmp" "    host: 192.0.2.1"
  case_body() {
    CONFIG_FILE="$CONFIG"
    GID_IN="$RANGE_LO"
    check_ping
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"icmp: unprivileged ping sockets allowed for gid=$RANGE_LO"* ]] || return 1
  [[ $output != *"WARN"* ]] || return 1
}

@test "check_ping warns on a gid outside ping_group_range" {
  ping_range
  write_config "targets:" "  - name: gateway" "    type: icmp" "    host: 192.0.2.1"
  case_body() {
    CONFIG_FILE="$CONFIG"
    GID_IN=$((RANGE_HI + 1))
    check_ping
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"is outside net.ipv4.ping_group_range ($RANGE_LO $RANGE_HI)"* ]] || return 1
  [[ $output == *"net.ipv4.ping_group_range=\"0 2147483647\""* ]] || return 1
}

@test "listen address port feeds the port check" {
  case_body() {
    echo "PORTS_INTERNAL=$PORTS_INTERNAL"
  }

  LATENCY_EXPORTER_ADDR=127.0.0.1:9555 run in_entrypoint case_body
  [[ $output == *"PORTS_INTERNAL=9555"* ]] || return 1

  LATENCY_EXPORTER_ADDR= run in_entrypoint case_body
  [[ $output == *"PORTS_INTERNAL=9428"* ]] || return 1
}

@test "check_ports warns on a held port" {
  case_body() {
    listening_ports() { printf '22\n9428\n19428\n'; }
    PORTS_INTERNAL="9428"
    check_ports
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"port 9428 is already in use"* ]] || return 1
}

@test "check_ports stays quiet on a free port" {
  case_body() {
    listening_ports() { printf '22\n19428\n94280\n'; }
    PORTS_INTERNAL="9428"
    check_ports
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ] || return 1
}

@test "check_ports skips an empty port list" {
  case_body() {
    listening_ports() { echo "listening_ports called"; }
    PORTS_INTERNAL=""
    check_ports
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ] || return 1
}

@test "listening_ports reports a real listener" {
  command -v nc >/dev/null 2>&1 || skip "nc is not installed"
  [ -r /proc/net/tcp ] || skip "/proc/net/tcp is not readable"
  nc -l -p 45679 >/dev/null 2>&1 &
  local pid=$!
  local i
  for i in $(seq 50); do
    grep -q ':B26F ' /proc/net/tcp /proc/net/tcp6 2>/dev/null && break
    sleep 0.1
  done

  run in_entrypoint listening_ports
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  [ "$status" -eq 0 ] || return 1
  printf '%s\n' "$output" | grep -qx 45679 || return 1
}

caps_case() {
  CAPEFF="$1"
  case_body() {
    awk() {
      case "$*" in
        *CapEff*) printf '%s\n' "$CAPEFF" ;;
        *) command awk "$@" ;;
      esac
    }
    check_caps
  }
  run in_entrypoint case_body
}

@test "check_caps reports unreadable status" {
  caps_case ""

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"capabilities: could not read /proc/self/status"* ]] || return 1
}

@test "check_caps is happy with every capability dropped" {
  caps_case 0000000000000000

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"capabilities: all dropped (CapEff=0000000000000000); good"* ]] || return 1
}

@test "check_caps recognises the docker default set" {
  caps_case 00000000a80425fb

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"docker default set only (chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap)"* ]] || return 1
  [[ $output != *"WARN"* ]] || return 1
}

@test "check_caps warns on capabilities beyond the default" {
  caps_case 00000080a82435fb

  [ "$status" -eq 0 ] || return 1
  [[ $output == *"elevated capabilities present beyond the docker default: net_admin sys_admin bpf"* ]] || return 1
  [[ $output == *"cap_drop: [ALL]"* ]] || return 1
}

mountinfo_case() {
  MOUNTINFO="$CASE_DIR/mountinfo"
  mkdir -p "$CASE_DIR/config" "$CASE_DIR/data" "$CASE_DIR/scratch" "$CASE_DIR/opt" "$CASE_DIR/required"
  cat > "$MOUNTINFO" <<MI
22 1 0:21 / / rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
23 22 0:22 / /proc rw,nosuid,nodev,noexec - proc proc rw
24 22 0:23 / /sys ro,nosuid - sysfs sysfs ro
30 22 8:1 /volumes/config $CASE_DIR/config ro,relatime - ext4 /dev/vda1 rw
31 22 8:1 /volumes/data $CASE_DIR/data rw,relatime - ext4 /dev/vda1 rw
32 22 8:1 /volumes/data $CASE_DIR/data rw,relatime - ext4 /dev/vda1 rw
33 22 8:1 /volumes/hosts /etc/hosts rw,relatime - ext4 /dev/vda1 rw
34 22 8:1 /volumes/resolv /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw
35 22 0:40 / $CASE_DIR/scratch rw,nosuid - tmpfs tmpfs rw
36 22 8:1 /volumes/gone $CASE_DIR/gone rw,relatime - ext4 /dev/vda1 rw
37 22 8:2 /volumes/opt $CASE_DIR/opt rw,relatime shared:4 master:1 - xfs /dev/vdb1 rw
MI
  case_body() {
    awk() {
      local last="${*: -1}"
      if [ "$last" = /proc/self/mountinfo ]; then
        set -- "${@:1:$#-1}" "$MOUNTINFO"
      fi
      command awk "$@"
    }
    REQUIRED_RW="$1"
    collect_mounts
    printf 'mount=%s\n' "${MOUNTS[@]}"
  }
  run in_entrypoint case_body "$1"
}

@test "collect_mounts keeps user mounts and drops system ones" {
  mountinfo_case ""

  [ "$status" -eq 0 ] || return 1
  [ "$output" = "mount=$CASE_DIR/config
mount=$CASE_DIR/data
mount=$CASE_DIR/opt" ] || return 1
}

@test "collect_mounts lists required volumes first without duplicates" {
  mountinfo_case "$CASE_DIR/required $CASE_DIR/data $CASE_DIR/required"

  [ "$status" -eq 0 ] || return 1
  [ "$output" = "mount=$CASE_DIR/required
mount=$CASE_DIR/data
mount=$CASE_DIR/config
mount=$CASE_DIR/opt" ] || return 1
}

@test "collect_mounts yields nothing without mountinfo" {
  case_body() {
    awk() {
      local last="${*: -1}"
      if [ "$last" = /proc/self/mountinfo ]; then
        set -- "${@:1:$#-1}" "$CASE_DIR/absent"
      fi
      command awk "$@"
    }
    REQUIRED_RW=""
    collect_mounts
    echo "count=${#MOUNTS[@]}"
  }

  run in_entrypoint case_body

  [ "$status" -eq 0 ] || return 1
  [ "$output" = "count=0" ] || return 1
}
