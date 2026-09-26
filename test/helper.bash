REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="$REPO_ROOT/docker/entrypoint.sh"

in_entrypoint() {
  (
    . <(awk '/^info "starting preflight checks"$/ { exit } { print }' "$ENTRYPOINT")
    set +e
    "$@"
  ) 2>&1
}

skip_as_root() {
  if [ "$(id -u)" = "0" ]; then
    skip "uid 0 reads anything"
  fi
  return 0
}

ping_range() {
  local range=/proc/sys/net/ipv4/ping_group_range
  [ -r "$range" ] || skip "ping_group_range is not exposed here"
  read -r RANGE_LO RANGE_HI < "$range"
}
