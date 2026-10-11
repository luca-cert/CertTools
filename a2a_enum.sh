#!/usr/bin/env bash
# a2a_enum.sh - Enumerate A2A agents on one or more hosts by fetching their Agent Cards.
#
# Usage:
#   ./a2a_enum.sh [options] <ip> [<ip> ...]
#
# Options:
#   -p RANGE   Port or port range to scan (default: 8000-8010), e.g. -p 9000 or -p 8000-8100
#   -f FILE    Read target IPs from FILE (one per line, '#' comments allowed)
#   -t SECS    Per-request timeout in seconds (default: 2)
#   -o DIR     Save raw agent cards to DIR as <ip>_<port>.json
#   -r         Print full raw JSON instead of the summary
#   -h         Show this help
#
# Targets may be IPv4 or IPv6 addresses. Use "-" with -f to read from stdin.
# Port discovery uses nmap when installed (falls back to curl probing).
# Required: curl, jq.  Optional: nmap.
#
# Examples:
#   ./a2a_enum.sh 192.168.50.25
#   ./a2a_enum.sh -p 8000-8100 -o ./cards 10.0.0.5 10.0.0.6
#   ./a2a_enum.sh -f targets.txt
#   ./a2a_enum.sh fe80::1
#
# Only scan hosts you own or are authorised to test.

set -uo pipefail

START=8000
END=8010
TIMEOUT=2
OUTDIR=""
RAW=0
TARGET_FILE=""

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; }
die()   { echo "Error: $*" >&2; exit 1; }

# ---------- argument parsing ----------
while getopts ":p:f:t:o:rh" opt; do
  case "$opt" in
    p) PORT_RANGE="$OPTARG" ;;
    f) TARGET_FILE="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    r) RAW=1 ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument" ;;
    *) die "Unknown option -$OPTARG (see -h)" ;;
  esac
done
shift $((OPTIND - 1))

if [[ -n "${PORT_RANGE:-}" ]]; then
  if [[ "$PORT_RANGE" =~ ^([0-9]+)-([0-9]+)$ ]]; then
    START="${BASH_REMATCH[1]}"; END="${BASH_REMATCH[2]}"
  elif [[ "$PORT_RANGE" =~ ^[0-9]+$ ]]; then
    START="$PORT_RANGE"; END="$PORT_RANGE"
  else
    die "Invalid port range '$PORT_RANGE' (use N or N-M)"
  fi
fi
(( START >= 1 && END <= 65535 && START <= END )) || die "Ports must satisfy 1 <= start <= end <= 65535"
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "Timeout must be a whole number of seconds"

# ---------- IP validation ----------
is_ipv4() {
  local ip="$1" IFS=. octet
  local -a o
  read -ra o <<<"$ip"
  [[ ${#o[@]} -eq 4 ]] || return 1
  for octet in "${o[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}

is_ipv6() {
  local ip="$1" colons="${1//[^:]/}"
  [[ "$ip" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  (( ${#colons} >= 2 && ${#colons} <= 7 )) || return 1
  [[ "$ip" != *:::* ]] || return 1
}

# ---------- collect targets ----------
TARGETS=("$@")
if [[ -n "$TARGET_FILE" ]]; then
  if [[ "$TARGET_FILE" == "-" ]]; then
    src=/dev/stdin
  else
    [[ -r "$TARGET_FILE" ]] || die "Cannot read target file '$TARGET_FILE'"
    src="$TARGET_FILE"
  fi
  while IFS= read -r line; do
    line="${line%%#*}"; line="${line//[[:space:]]/}"
    [[ -n "$line" ]] && TARGETS+=("$line")
  done < "$src"
fi
[[ ${#TARGETS[@]} -gt 0 ]] || { usage >&2; exit 1; }

VALID=()
for t in "${TARGETS[@]}"; do
  t="${t#[}"; t="${t%]}"            # allow [::1] style
  if is_ipv4 "$t" || is_ipv6 "$t"; then
    VALID+=("$t")
  else
    echo "Skipping invalid IP address: $t" >&2
  fi
done
[[ ${#VALID[@]} -gt 0 ]] || die "No valid IP addresses given"

# ---------- dependencies ----------
for bin in curl jq; do
  command -v "$bin" >/dev/null 2>&1 || die "Missing dependency: $bin"
done
[[ -n "$OUTDIR" ]] && mkdir -p "$OUTDIR"

# Current A2A spec uses agent-card.json; older versions used agent.json.
CARD_PATHS=("/.well-known/agent-card.json" "/.well-known/agent.json")

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

summarize() {
  jq -r '
    "  Name:         \(.name // "n/a")",
    "  Version:      \(.version // "n/a")",
    "  Protocol:     \(.protocolVersion // "n/a")",
    "  Endpoint URL: \(.url // "n/a")",
    "  Description:  \(.description // "n/a")",
    "  Capabilities: \((.capabilities // {}) | to_entries | map("\(.key)=\(.value|tojson)") | join(", "))",
    "  Input modes:  \((.defaultInputModes // []) | join(", "))",
    "  Output modes: \((.defaultOutputModes // []) | join(", "))",
    "  Auth:         \((.securitySchemes // .authentication // {}) | tojson)",
    "  Ext. card:    \(.supportsAuthenticatedExtendedCard // false)",
    "  Skills (\((.skills // []) | length)):",
    ((.skills // [])[] |
      "    - [\(.id // "?")] \(.name // "?"): \(.description // "")",
      "        tags: \((.tags // []) | join(", "))"
    )
  ' "$1"
}

TOTAL=0

scan_host() {
  local host="$1" hosturl="$host" safe="${1//[:.]/_}" port path url code hit p
  local -a nmap_extra=() PORTS=()

  if is_ipv6 "$host"; then
    hosturl="[$host]"
    nmap_extra=(-6)
  fi

  echo
  echo "=== ${host} (ports ${START}-${END}) ==="

  # Phase 1: port discovery
  if command -v nmap >/dev/null 2>&1; then
    while read -r p; do
      PORTS+=("$p")
    done < <(nmap ${nmap_extra[@]+"${nmap_extra[@]}"} -Pn -n --open -p "${START}-${END}" -oG - "$host" 2>/dev/null \
              | grep -oE '[0-9]+/open' | cut -d/ -f1)
    echo "nmap found ${#PORTS[@]} open port(s): ${PORTS[*]:-none}"
  else
    echo "nmap not found, probing every port with curl"
    for ((p = START; p <= END; p++)); do PORTS+=("$p"); done
  fi

  # Phase 2: fetch agent cards
  for port in ${PORTS[@]+"${PORTS[@]}"}; do
    hit=0
    for path in "${CARD_PATHS[@]}"; do
      url="http://${hosturl}:${port}${path}"
      code="$(curl -s -g --connect-timeout 1 --max-time "$TIMEOUT" \
              -o "$tmp" -w '%{http_code}' "$url" 2>/dev/null || true)"

      [[ "$code" == "200" ]] || continue
      jq -e 'type == "object" and has("name")' "$tmp" >/dev/null 2>&1 || continue

      hit=1
      TOTAL=$((TOTAL + 1))
      echo
      echo "[+] Agent found: ${url}"
      if [[ "$RAW" == "1" ]]; then jq . "$tmp"; else summarize "$tmp"; fi
      [[ -n "$OUTDIR" ]] && jq . "$tmp" > "${OUTDIR}/${safe}_${port}.json"
      break
    done
    [[ $hit -eq 0 ]] && echo "[-] ${host}:${port} no agent card"
  done
}

for host in "${VALID[@]}"; do
  scan_host "$host"
done

echo
echo "Done. ${TOTAL} agent(s) found across ${#VALID[@]} host(s)."
