#!/usr/bin/env python3
"""
enrich_metadata.py
Input: out/results.json (from snapworker) or targets.txt
Output: out/enriched.json and out/enriched.csv plus a run log out/enrich.log

What it collects per URL/hostname:
 - detection_time_utc, detection_time_ist
 - input URL, used_url (if fallback used)
 - screenshot file (if any)
 - hostname, resolved IPs (A/AAAA)
 - ASN, as_owner, as_country (via ipwhois)
 - registrar, creation_date, expiration_date, whois_raw
 - MX records
 - TLS certificate: issuer, notBefore, notAfter, subjectAltNames (if TLS reachable)
 - source (string you pass; default "screenshot-worker")
 - execution_log (small notes)
 - remarks (empty by default)
"""
import os, sys, json, csv, socket, ssl, datetime, time
from urllib.parse import urlparse
import whois
from ipwhois import IPWhois
import dns.resolver
import tldextract
import requests
import pytz

OUTDIR = "out"
RESULTS_JSON = os.path.join(OUTDIR, "results.json")
ENRICHED_JSON = os.path.join(OUTDIR, "enriched.json")
ENRICHED_CSV  = os.path.join(OUTDIR, "enriched.csv")
RUN_LOG = os.path.join(OUTDIR, "enrich.log")

# helper functions
def now_utc_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def now_ist_iso():
    ist = pytz.timezone("Asia/Kolkata")
    return datetime.datetime.now(ist).isoformat()

def safe_resolve(host):
    ips = []
    try:
        for res in socket.getaddrinfo(host, None):
            ip = res[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception as e:
        return [], str(e)
    return ips, ""

def get_asn_info(ip):
    try:
        obj = IPWhois(ip)
        r = obj.lookup_rdap(asn_methods=["whois", "http"])
        asn = r.get("asn")
        asn_cidr = r.get("asn_cidr")
        asn_country = r.get("asn_country_code")
        asn_org = r.get("network", {}).get("name") or r.get("network", {}).get("remarks", "")
        return {"asn": asn, "asn_cidr": asn_cidr, "asn_country": asn_country, "asn_org": asn_org}
    except Exception as e:
        return {"error": str(e)}

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar if hasattr(w, "registrar") else None,
            "creation_date": str(w.creation_date) if getattr(w, "creation_date", None) else None,
            "expiration_date": str(w.expiration_date) if getattr(w, "expiration_date", None) else None,
            "name_servers": w.name_servers if getattr(w, "name_servers", None) else None,
            "whois_raw": str(w.text)[:10000]  # cap raw to 10k chars
        }
    except Exception as e:
        return {"error": str(e)}

def get_mx_records(domain):
    try:
        ans = dns.resolver.resolve(domain, 'MX', lifetime=8)
        mxs = []
        for r in ans:
            parts = str(r).split()
            if len(parts) >= 2:
                mxs.append(parts[1].strip('.'))
        return mxs
    except Exception as e:
        return []

def get_tls_info(host, port=443, timeout=6):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', ())) if cert.get('issuer') else {}
                notBefore = cert.get('notBefore')
                notAfter  = cert.get('notAfter')
                subject = dict(x[0] for x in cert.get('subject', ())) if cert.get('subject') else {}
                san = []
                for k,v in cert.items():
                    if k == 'subjectAltName':
                        san = [x[1] for x in v]
                return {"issuer": issuer, "subject": subject, "notBefore": notBefore, "notAfter": notAfter, "san": san}
    except Exception as e:
        return {"error": str(e)}

def sanitize_domain(host):
    # reduce to registered domain where possible
    try:
        ext = tldextract.extract(host)
        if ext.registered_domain:
            return ext.registered_domain
    except Exception:
        pass
    return host

def enrich_item(item, source="screenshot-worker"):
    """
    item example keys: input, used_url, status, file, error
    """
    rec = {}
    rec["detection_time_utc"] = now_utc_iso()
    rec["detection_time_ist"] = now_ist_iso()
    rec["source"] = source
    rec.update(item)

    raw_url = item.get("used_url") or item.get("input") or ""
    parsed = urlparse(raw_url if raw_url else item.get("input",""))
    host = parsed.hostname or raw_url or item.get("input","")
    if ":" in host:
        host = host.split(":")[0]

    rec["hostname"] = host
    rec["registered_domain"] = sanitize_domain(host)

    # DNS resolution
    ips, ip_err = safe_resolve(host)
    rec["resolved_ips"] = ips
    rec["dns_error"] = ip_err

    # ASN info - use first IP if available
    rec["asn_info"] = None
    if ips:
        asinfos = []
        for ip in ips[:2]:
            ai = get_asn_info(ip)
            asinfos.append({ip: ai})
        rec["asn_info"] = asinfos

    # WHOIS
    who = get_whois(rec["registered_domain"])
    rec["whois"] = who

    # MX
    rec["mx_records"] = get_mx_records(rec["registered_domain"])

    # TLS/cert (try host)
    rec["tls"] = get_tls_info(host)

    # remark placeholder
    rec["remarks"] = ""

    # small execution log entry
    rec["execution_log"] = f"enriched_at={now_utc_iso()}"

    return rec

def main():
    src = RESULTS_JSON
    if not os.path.exists(src):
        print("No results.json found at out/results.json; pass --input <file> to use a different file", file=sys.stderr)
        sys.exit(1)

    with open(src, "r", encoding="utf8") as fh:
        items = json.load(fh)

    enriched = []
    with open(RUN_LOG, "a", encoding="utf8") as logf:
        logf.write(f"=== Enrich run at {now_utc_iso()} ===\n")
        for it in items:
            try:
                rec = enrich_item(it, source="screenshot-worker")
                enriched.append(rec)
                logf.write(f"OK {rec.get('hostname')} -> IPs:{rec.get('resolved_ips')}\n")
            except Exception as e:
                logf.write(f"ERR processing {it.get('input')}: {e}\n")

    # write enriched JSON and CSV
    with open(ENRICHED_JSON, "w", encoding="utf8") as oh:
        json.dump(enriched, oh, indent=2)

    # CSV field order
    fields = ["detection_time_utc","detection_time_ist","source","input","used_url","status","file","hostname","registered_domain","resolved_ips","asn_info","whois","mx_records","tls","remarks","execution_log"]
    with open(ENRICHED_CSV, "w", encoding="utf8", newline="") as ch:
        writer = csv.writer(ch)
        writer.writerow(fields)
        for r in enriched:
            row = [ r.get(f) if f not in ("resolved_ips","asn_info","whois","mx_records","tls") else json.dumps(r.get(f)) for f in fields ]
            writer.writerow(row)

    print(f"Wrote {ENRICHED_JSON} and {ENRICHED_CSV} and appended run log {RUN_LOG}")

if __name__ == "__main__":
    main()
