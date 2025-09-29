#!/usr/bin/env bash
# find_phish_nobruteforce_with_whois.sh
# Same usage as prior script, with WHOIS/DNS enrichment added.
# Usage:
#   ./find_phish_nobruteforce_with_whois.sh <domain-or-brand> [--tokens tokens_file] [--tlds tlds_file] [--threads N]
# Example:
#   ./find_phish_nobruteforce_with_whois.sh airtel --threads 40
#
# Safety: do not use this against targets you are not authorized to probe.
set -uo pipefail
IFS=$'\n\t'

# Defaults
THREADS=50
TIMEOUT=8
OUTDIR_PREFIX="recon"
DEFAULT_TLDS=(in com net org co xyz top site online biz info)

print_help(){
  cat <<'EOF'
Usage: $0 <domain-or-brand> [--tokens tokens_file] [--tlds tlds_file] [--threads N] [--dry-run]
Options:
  --tokens <file>   Use dnstwist dictionary file (requires dnstwist installed).
  --tlds <file>     Provide a file with TLDs (one per line) to expand brand-only input.
  --threads <n>     Number of concurrent threads for httpx (default: 50).
  --dry-run         Do not run network probes; just build candidate lists.
  --no-httpx        Force curl fallback instead of httpx.
  --help            Show this help and exit.
EOF
}

if [ $# -lt 1 ]; then
  echo "Usage: $0 <domain-or-brand> [--tokens tokens_file] [--tlds tlds_file] [--threads N] [--dry-run]"
  exit 1
fi

INPUT="$1"; shift
TOKFILE=""
TLD_FILE=""
DRY_RUN=0
NO_HTTPX=0

while [ $# -gt 0 ]; do
  case "$1" in
    --tokens) TOKFILE="$2"; shift 2 ;;
    --tlds) TLD_FILE="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-httpx) NO_HTTPX=1; shift ;;
    --help) print_help; exit 0 ;;
    *) echo "Unknown option: $1"; print_help; exit 2 ;;
  esac
done

# TLD list resolution
if [ -n "${TLD_FILE:-}" ] && [ -f "$TLD_FILE" ]; then
  mapfile -t TLDs < <(sed '/^\s*$/d; s/\r$//' "$TLD_FILE")
elif [ -n "${TLD_LIST:-}" ]; then
  read -ra TLDs <<< "$TLD_LIST"
else
  TLDs=("${DEFAULT_TLDS[@]}")
fi

# Brand vs full domain
if [[ "$INPUT" == *.* ]]; then
  DOMAIN="$INPUT"
  OUTDIR="${OUTDIR_PREFIX}_${DOMAIN//[^a-zA-Z0-9._-]/_}"
  DOMAIN_LIST=("$DOMAIN")
  BASE_TOKEN="$DOMAIN"
else
  BRAND="$INPUT"
  OUTDIR="${OUTDIR_PREFIX}_${BRAND//[^a-zA-Z0-9._-]/_}"
  DOMAIN_LIST=()
  for t in "${TLDs[@]}"; do
    DOMAIN_LIST+=("${BRAND}.${t}")
  done
  BASE_TOKEN="$BRAND"
  echo "[*] Brand-only detected: expanding to domains: ${DOMAIN_LIST[*]}"
fi

mkdir -p "$OUTDIR/crt_sh_json"
CRT_JSON_DIR="$OUTDIR/crt_sh_json"
CRT_DOMS="$OUTDIR/crt_domains.txt"
GAU_URLS="$OUTDIR/gau_urls.txt"
DNSTWIST_OUT="$OUTDIR/dnstwist_tokens.txt"
CAND_ALL="$OUTDIR/candidates_all.txt"
PROBED_TXT="$OUTDIR/probed.txt"
PROBED_CSV="$OUTDIR/probed.csv"
SUSPECT_TXT="$OUTDIR/suspect_keyword_hits.txt"
BRAND_LIST="$OUTDIR/brand_hits.txt"

: > "$CRT_DOMS"
: > "$GAU_URLS"
: > "$DNSTWIST_OUT"
: > "$PROBED_TXT"
: > "$PROBED_CSV"

echo "[*] Tools check..."
missing=()
for cmd in curl jq; do
  command -v $cmd >/dev/null 2>&1 || missing+=("$cmd")
done
HAVE_GAU=0; HAVE_HTTPX=0
if command -v gau >/dev/null 2>&1; then HAVE_GAU=1; fi
if command -v httpx >/dev/null 2>&1 && [ $NO_HTTPX -eq 0 ]; then HAVE_HTTPX=1; fi
if [ -n "$TOKFILE" ]; then
  command -v dnstwist >/dev/null 2>&1 || missing+=("dnstwist (required with --tokens)")
fi
# optional enrichment tools
HAVE_WHOIS=0; HAVE_DIG=0; HAVE_HOST=0; HAVE_CYMRU=0
command -v whois >/dev/null 2>&1 && HAVE_WHOIS=1
command -v dig >/dev/null 2>&1 && HAVE_DIG=1
command -v host >/dev/null 2>&1 && HAVE_HOST=1
# check for Cymru whois (for ASN) - optional
if command -v whois >/dev/null 2>&1; then
  whois -h whois.cymru.com 2>/dev/null | head -n1 >/dev/null 2>&1 && HAVE_CYMRU=1 || HAVE_CYMRU=0
fi

if [ ${#missing[@]} -gt 0 ]; then
  echo "Missing required tools: ${missing[*]}"
  echo "Install them and re-run. Example: sudo apt install curl jq whois dnsutils; go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  exit 2
fi

UA="find_phish_nobruteforce/1.0 (+https://your-organization.example/)"

echo "[*] 1) crt.sh collection"
if [[ -n "${BRAND:-}" && "$INPUT" == "$BRAND" ]]; then
  CRT_QUERY="%25${BRAND}%25"
  OUTFILE="$CRT_JSON_DIR/crt_sh_brand.json"
  curl -s -A "$UA" "https://crt.sh/?q=${CRT_QUERY}&output=json" -o "$OUTFILE" || true
  if [ -s "$OUTFILE" ]; then
    jq -r '.[].name_value' "$OUTFILE" 2>/dev/null | sed 's/^\*\.//' | tr '[:upper:]' '[:lower:]' >> "$CRT_DOMS" || true
  else
    echo "    [!] crt.sh empty/blocked for brand ${BRAND}"
  fi
else
  for D in "${DOMAIN_LIST[@]}"; do
    OUTFILE="$CRT_JSON_DIR/crt_sh_${D//[^a-zA-Z0-9._-]/_}.json"
    curl -s -A "$UA" "https://crt.sh/?q=%25${D}%25&output=json" -o "$OUTFILE" || true
    if [ -s "$OUTFILE" ]; then
      jq -r '.[].name_value' "$OUTFILE" 2>/dev/null | sed 's/^\*\.//' | tr '[:upper:]' '[:lower:]' >> "$CRT_DOMS" || true
    else
      echo "    [!] crt.sh empty/blocked for ${D}"
    fi
  done
fi
[ -s "$CRT_DOMS" ] && sort -u "$CRT_DOMS" -o "$CRT_DOMS"
echo "[+] crt.sh domains:" $( [ -f "$CRT_DOMS" ] && wc -l < "$CRT_DOMS" || echo 0 )

echo "[*] 2) gau (historical) collection (if available)"
if [ $HAVE_GAU -eq 1 ]; then
  for D in "${DOMAIN_LIST[@]}"; do
    gau --subs "$D" 2>/dev/null | awk -F/ '{print $3}' | tr '[:upper:]' '[:lower:]' | sed '/^\s*$/d' >> "$GAU_URLS" || true
  done
  [ -s "$GAU_URLS" ] && sort -u "$GAU_URLS" -o "$GAU_URLS"
  echo "[+] gau hostnames:" $( [ -f "$GAU_URLS" ] && wc -l < "$GAU_URLS" || echo 0 )
else
  echo "  - gau not installed; skipping"
fi

echo "[*] 3) dnstwist (optional dictionary) collection"
if [ -n "$TOKFILE" ] && [ -f "$TOKFILE" ]; then
  for D in "${DOMAIN_LIST[@]}"; do
    dnstwist --registered --format json --dictionary "$TOKFILE" "$D" 2>/dev/null | jq -r '.[].domain' 2>/dev/null | tr '[:upper:]' '[:lower:]' >> "$DNSTWIST_OUT" || true
  done
  [ -s "$DNSTWIST_OUT" ] && sort -u "$DNSTWIST_OUT" -o "$DNSTWIST_OUT"
  echo "[+] dnstwist candidates:" $( [ -f "$DNSTWIST_OUT" ] && wc -l < "$DNSTWIST_OUT" || echo 0 )
else
  echo "[*] Skipping dnstwist (no tokens)"
fi

echo "[*] 4) Combine candidates"
cat "$CRT_DOMS" "$GAU_URLS" "$DNSTWIST_OUT" 2>/dev/null | sed -E 's#[:/].*$##' | sed '/^\s*$/d' | sed 's/^\.*//; s/\.$//' | tr '[:upper:]' '[:lower:]' | sort -u > "$CAND_ALL" || true
echo "[+] total candidates:" $( [ -f "$CAND_ALL" ] && wc -l < "$CAND_ALL" || echo 0 )

echo "[*] 5) Brand token hits"
grep -i "$BASE_TOKEN" "$CAND_ALL" | sort -u > "$BRAND_LIST" || true
echo "[+] brand-token hits:" $( [ -f "$BRAND_LIST" ] && wc -l < "$BRAND_LIST" || echo 0 )

if [ $DRY_RUN -eq 1 ]; then
  echo "[*] Dry-run: stopping before active probing."
  exit 0
fi

echo "[*] 6) Probe candidates (httpx preferred, fallback to curl)"
: > "$PROBED_TXT"
echo "host,status_code,title,location,ip,asn,registrar,created,expires,nameservers" > "$PROBED_CSV"

if [ $HAVE_HTTPX -eq 1 ]; then
  cat "$CAND_ALL" | httpx -silent -status-code -title -location -threads "$THREADS" -timeout "$TIMEOUT" -o "$PROBED_TXT" || true
  while IFS= read -r line; do
    host=$(echo "$line" | awk '{print $1}')
    status=$(echo "$line" | sed -n 's/.*\[\([0-9][0-9][0-9]\)\].*/\1/p')
    title=$(echo "$line" | sed -n 's/.*\] \(.*\) (location:.*/\1/p')
    [ -z "$title" ] && title=$(echo "$line" | sed -n 's/.*\] \(.*\)$/\1/p')
    location=$(echo "$line" | grep -oP '\(location:\s*\K[^)]+' || true)

    # DNS/WHOIS enrichment (best-effort)
    ip=""; asn=""; registrar=""; created=""; expires=""; nameservers=""
    if [ $HAVE_DIG -eq 1 ]; then
      ip=$(dig +short A "$host" | head -n1 || true)
      [ -z "$ip" ] && ip=$(dig +short AAAA "$host" | head -n1 || true)
    elif [ $HAVE_HOST -eq 1 ]; then
      ip=$(host "$host" 2>/dev/null | awk '/has address/ {print $4; exit}' || true)
    fi

    if [ -n "$ip" ] && [ $HAVE_WHOIS -eq 1 ]; then
      # ASN via Team Cymru (best-effort)
      if [ $HAVE_CYMRU -eq 1 ]; then
        asn=$(printf "%s\n" " -v $ip" | whois -h whois.cymru.com 2>/dev/null | awk -F'|' 'NR==2{gsub(/^[ \t]+|[ \t]+$/,"",$1); print $1}' || true)
      else
        # try generic whois parsing for 'origin' lines
        asn=$(whois "$ip" 2>/dev/null | grep -Ei 'origin|originas|asn' | head -n1 || true)
        asn=$(echo "$asn" | tr -d '\n' | sed 's/^ *//; s/ *$//' )
      fi
      # domain WHOIS (may vary across TLDs)
      who_raw=$(whois "$host" 2>/dev/null || true)
      registrar=$(echo "$who_raw" | grep -i 'registrar:' | head -n1 | sed 's/^[Rr]egistrar:[[:space:]]*//g' || true)
      created=$(echo "$who_raw" | grep -Ei 'creation date:|created on:|domain create date:' | head -n1 | sed -E 's/^[^:]+:[[:space:]]*//g' || true)
      expires=$(echo "$who_raw" | grep -Ei 'expiry date:|expiration date:|registrar registration expiration date:' | head -n1 | sed -E 's/^[^:]+:[[:space:]]*//g' || true)
      nameservers=$(echo "$who_raw" | grep -Ei '^name server:|^nserver:|^nameserver:' | sed -E 's/^[^:]+:[[:space:]]*//g' | tr '\n' ';' | sed 's/;*$//' || true)
    fi

    # sanitize title & fields
    title=$(echo "$title" | tr '\n' ' ' | sed 's/"/'\''/g' | sed 's/^\s*//; s/\s*$//')
    registrar=$(echo "$registrar" | tr -d '\r' | sed 's/"/'\''/g')
    created=$(echo "$created" | tr -d '\r')
    expires=$(echo "$expires" | tr -d '\r')
    nameservers=$(echo "$nameservers" | tr -d '\r')

    echo "$host [$status] $title (location: $location)" >> "$PROBED_TXT"
    printf '%s,%s,"%s","%s","%s","%s","%s","%s","%s"\n' "$host" "${status:-}" "${title:-}" "${location:-}" "${ip:-}" "${asn:-}" "${registrar:-}" "${created:-}" "${expires:-}" >> "$PROBED_CSV"
  done < "$PROBED_TXT"
else
  # curl fallback
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    url="https://$host"
    code=$(curl -I -sL --max-time "$TIMEOUT" -A "$UA" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
    if [ -z "$code" ] || [ "$code" = "000" ]; then
      url="http://$host"
      code=$(curl -I -sL --max-time "$TIMEOUT" -A "$UA" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
    fi
    body=$(curl -sL --max-time "$TIMEOUT" -A "$UA" "$url" 2>/dev/null || true)
    title=$(echo "$body" | tr '\n' ' ' | sed -n 's/.*<title[^>]*>\(.*\)<\/title>.*/\1/ip;T;p' | sed 's/"/'\''/g')

    ip=""; asn=""; registrar=""; created=""; expires=""; nameservers=""
    if [ $HAVE_DIG -eq 1 ]; then
      ip=$(dig +short A "$host" | head -n1 || true)
      [ -z "$ip" ] && ip=$(dig +short AAAA "$host" | head -n1 || true)
    elif [ $HAVE_HOST -eq 1 ]; then
      ip=$(host "$host" 2>/dev/null | awk '/has address/ {print $4; exit}' || true)
    fi

    if [ -n "$ip" ] && [ $HAVE_WHOIS -eq 1 ]; then
      if [ $HAVE_CYMRU -eq 1 ]; then
        asn=$(printf "%s\n" " -v $ip" | whois -h whois.cymru.com 2>/dev/null | awk -F'|' 'NR==2{gsub(/^[ \t]+|[ \t]+$/,"",$1); print $1}' || true)
      else
        asn=$(whois "$ip" 2>/dev/null | grep -Ei 'origin|originas|asn' | head -n1 || true)
        asn=$(echo "$asn" | tr -d '\n' | sed 's/^ *//; s/ *$//' )
      fi
      who_raw=$(whois "$host" 2>/dev/null || true)
      registrar=$(echo "$who_raw" | grep -i 'registrar:' | head -n1 | sed 's/^[Rr]egistrar:[[:space:]]*//g' || true)
      created=$(echo "$who_raw" | grep -Ei 'creation date:|created on:|domain create date:' | head -n1 | sed -E 's/^[^:]+:[[:space:]]*//g' || true)
      expires=$(echo "$who_raw" | grep -Ei 'expiry date:|expiration date:|registrar registration expiration date:' | head -n1 | sed -E 's/^[^:]+:[[:space:]]*//g' || true)
      nameservers=$(echo "$who_raw" | grep -Ei '^name server:|^nserver:|^nameserver:' | sed -E 's/^[^:]+:[[:space:]]*//g' | tr '\n' ';' | sed 's/;*$//' || true)
    fi

    title=$(echo "$title" | tr '\n' ' ' | sed 's/"/'\''/g' | sed 's/^\s*//; s/\s*$//')
    echo "$host [$code] $title" >> "$PROBED_TXT"
    printf '%s,%s,"%s","%s","%s","%s","%s","%s","%s"\n' "$host" "${code:-}" "${title:-}" "" "${ip:-}" "${asn:-}" "${registrar:-}" "${created:-}" "${expires:-}" >> "$PROBED_CSV"
  done < "$CAND_ALL"
fi

echo "[+] Probing + enrichment done."
echo "[*] Filtering suspects by keyword"
KEYWORDS="login|signin|secure|account|verify|update|otp|pay|billing|recharge|bank|user|portal|auth"
grep -Ei "$KEYWORDS" "$PROBED_TXT" | sort -u > "$SUSPECT_TXT" || true
echo "[+] suspect-by-keyword:" $( [ -f "$SUSPECT_TXT" ] && wc -l < "$SUSPECT_TXT" || echo 0 )

echo
echo "Outputs in: $OUTDIR"
echo " - All candidates: $CAND_ALL"
echo " - Brand-token candidates: $BRAND_LIST"
echo " - Probed text: $PROBED_TXT"
echo " - Probed csv: $PROBED_CSV"
echo " - Suspects: $SUSPECT_TXT"
echo

# Print a quick note about missing enrichment tools
if [ $HAVE_WHOIS -eq 0 ] || ( [ $HAVE_DIG -eq 0 ] && [ $HAVE_HOST -eq 0 ] ); then
  echo "[!] WHOIS/DNS enrichment partially disabled because some tools are missing:"
  [ $HAVE_WHOIS -eq 0 ] && echo "    - whois not installed"
  [ $HAVE_DIG -eq 0 ] && [ $HAVE_HOST -eq 0 ] && echo "    - neither dig nor host installed"
  echo "    Install 'whois' and 'dnsutils' (for dig) to enable richer data."
fi

echo "Done."
