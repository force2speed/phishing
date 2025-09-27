#!/usr/bin/env bash
# find_phish_nobruteforce.sh
# Usage: ./find_phish_nobruteforce.sh <domain> [tokens_file]
# Example: ./find_phish_nobruteforce.sh airtel.in phish_tokens.txt
# Requires: curl, jq, gau, httpx, (optional) dnstwist

set -uo pipefail
IFS=$'\n\t'

if [ $# -lt 1 ]; then
  echo "Usage: $0 <domain> [tokens_file]"
  exit 1
fi

DOMAIN="$1"
TOKFILE="${2:-}"
OUTDIR="recon_${DOMAIN}"
mkdir -p "$OUTDIR"

echo "[*] Tools check..."
missing=()
for cmd in curl jq gau httpx; do
  command -v $cmd >/dev/null 2>&1 || missing+=("$cmd")
done
if [ -n "$TOKFILE" ]; then
  command -v dnstwist >/dev/null 2>&1 || missing+=("dnstwist (required when using tokens)")
fi
if [ ${#missing[@]} -gt 0 ]; then
  echo "Missing tools: ${missing[*]}"
  echo "Install them and re-run. (e.g. pip3 install dnstwist; go install ... httpx/gau)"
  exit 2
fi

echo "[*] 1) Collect Certificate Transparency domains (crt.sh)..."
# crt.sh JSON may be large; use jq to extract name_value fields
CRT_JSON="$OUTDIR/crt_sh.json"
CRT_DOMS="$OUTDIR/crt_domains.txt"
curl -s "https://crt.sh/?q=%25${DOMAIN}%25&output=json" > "$CRT_JSON" || true
if [ -s "$CRT_JSON" ]; then
  jq -r '.[].name_value' "$CRT_JSON" 2>/dev/null | sed 's/^\*\.//' | tr '[:upper:]' '[:lower:]' | sort -u > "$CRT_DOMS"
  echo "[+] crt.sh domains:" $(wc -l < "$CRT_DOMS")
else
  echo "[!] crt.sh returned no JSON or blocked; continuing without CT results."
  : > "$CRT_DOMS"
fi

echo "[*] 2) Collect historical URLs from public crawls (gau) for the domain and its subdomains..."
GAU_URLS="$OUTDIR/gau_urls.txt"
echo "$DOMAIN" | gau --subs 2>/dev/null | grep -i "$DOMAIN" | sed 's#^https\?://##I' | cut -d/ -f1 | tr '[:upper:]' '[:lower:]' | sort -u > "$GAU_URLS"
echo "[+] gau hostnames:" $(wc -l < "$GAU_URLS")

# Optional targeted tokens via dnstwist (registered-only)
DNSTWIST_OUT="$OUTDIR/dnstwist_tokens.txt"
if [ -n "$TOKFILE" ] && [ -f "$TOKFILE" ]; then
  echo "[*] 3) Running dnstwist with tokens (registered-only)..."
  # dnstwist outputs JSON array; extract .domain
  dnstwist --registered --format json --dictionary "$TOKFILE" "$DOMAIN" 2>/dev/null \
    | jq -r '.[].domain' 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u > "$DNSTWIST_OUT" || true
  echo "[+] dnstwist candidates:" $(wc -l < "$DNSTWIST_OUT")
else
  echo "[*] 3) Skipping dnstwist (no tokens provided)"
  : > "$DNSTWIST_OUT"
fi

echo "[*] 4) Combine candidate hostnames (dedup)"
CAND_ALL="$OUTDIR/candidates_all.txt"
cat "$CRT_DOMS" "$GAU_URLS" "$DNSTWIST_OUT" 2>/dev/null \
  | sed -E 's#[:/].*$##' \
  | sed '/^\s*$/d' \
  | sed 's/^\.*//; s/\.$//' \
  | sort -u > "$CAND_ALL"
echo "[+] total distinct candidates:" $(wc -l < "$CAND_ALL")

echo "[*] 5) Probe candidates (httpx) - status & title"
PROBED_TXT="$OUTDIR/probed.txt"
PROBED_JSON="$OUTDIR/probed.json"
# use httpx with moderate concurrency; adjust -threads if needed
cat "$CAND_ALL" | httpx -silent -status-code -title -location -threads 50 -timeout 8 -o "$PROBED_TXT" || true
# if httpx supports -json on your version, produce json-lines as well
if httpx -h 2>&1 | grep -q -- '-json'; then
  cat "$CAND_ALL" | httpx -silent -json -threads 50 -timeout 8 -o "$PROBED_JSON" || true
else
  : > "$PROBED_JSON"
fi
echo "[+] probed results saved to $PROBED_TXT"

echo "[*] 6) Filter suspect candidates by keyword heuristics"
# keywords (common phishing indicators)
KEYWORDS="login|signin|secure|account|verify|update|otp|pay|billing|recharge|bank|user|portal"
SUSPECT_TXT="$OUTDIR/suspect_keyword_hits.txt"
# PROBED_TXT lines often have format: hostname [status] title
grep -Ei "$KEYWORDS" "$PROBED_TXT" | sort -u > "$SUSPECT_TXT" || true
echo "[+] suspect-by-keyword:" $(wc -l < "$SUSPECT_TXT")

echo "[*] 7) Quick filter: brand token present (includes subdomains) - helps catch 'airtel-login' style hosts"
BRAND_LIST="$OUTDIR/brand_hits.txt"
grep -i "$DOMAIN" "$CAND_ALL" | sort -u > "$BRAND_LIST"
echo "[+] brand-token hits:" $(wc -l < "$BRAND_LIST")

echo "[*] 8) Produce final outputs"
echo "Probed file: $PROBED_TXT"
echo "JSON (if available): $PROBED_JSON"
echo "Suspect keyword hits: $SUSPECT_TXT"
echo "Brand-token candidates: $BRAND_LIST"
echo "All candidates: $CAND_ALL"

echo
echo "Next recommended steps:"
echo " - Review $SUSPECT_TXT and $BRAND_LIST; add high-scoring ones to a screenshot queue."
echo " - If you want scoring/WHOIS checks, run the Python enricher (I can provide it)."
echo " - For safe screenshots, use a VM or urlscan/webpagetest."
