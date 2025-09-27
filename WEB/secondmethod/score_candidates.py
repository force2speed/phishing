
#!/usr/bin/env python3
"""
score_candidates.py

Usage:
  python3 score_candidates.py --input recon_airtel.in/probed.json --brand airtel --out recon_airtel.in/scored.json
  or
  python3 score_candidates.py --input recon_airtel.in/probed.txt --brand airtel --out recon_airtel.in/scored.json

Produces:
  - scored.json : array of objects with fields {url, hostname, title, status, lev_distance, whois_days, suspicion_score, ip_asn}
  - scored.csv  : CSV summarizing key fields
"""
import argparse, json, re, sys, os, datetime
from urllib.parse import urlparse
import tldextract

# optional imports
try:
    import Levenshtein
except Exception:
    Levenshtein = None
try:
    import whois
except Exception:
    whois = None
try:
    from ipwhois import IPWhois
except Exception:
    IPWhois = None
import socket

PHISH_KEYWORDS = ['login','signin','secure','account','verify','update','otp','pay','billing','recharge','bank','user','portal','confirm','authenticate']

def parse_httpx_json_lines(path):
    objs = []
    with open(path, 'r', encoding='utf8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                objs.append(o)
            except Exception:
                # maybe the whole file is a JSON array
                try:
                    fh.seek(0)
                    data = json.load(fh)
                    if isinstance(data, list):
                        return data
                except Exception:
                    pass
    return objs

def parse_probed_txt(path):
    objs = []
    with open(path,'r',encoding='utf8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            # try pattern: url [status] ... [title]
            m = re.match(r'^(?P<url>\S+)\s*\[(?P<code>\d{3}|)\]\s*(?:\[(?P<br>\S*)\])?\s*(?P<title>.*)$', line)
            if m:
                url = m.group('url')
                code = m.group('code') or None
                title = m.group('title') or ''
            else:
                parts = line.split()
                url = parts[0]
                code = None
                title = ' '.join(parts[1:]) if len(parts)>1 else ''
            if not url.startswith('http://') and not url.startswith('https://'):
                url = 'https://' + url
            objs.append({'url': url, 'status_code': code, 'title': title})
    return objs

def hostname_from_url(url):
    try:
        p = urlparse(url)
        host = p.netloc or p.path
        host = host.split('@')[-1].split(':')[0]
        return host.lower()
    except:
        return url.lower()

def whois_age_days(hostname):
    if not whois:
        return None
    try:
        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        if isinstance(created, str):
            try:
                created = datetime.datetime.fromisoformat(created)
            except:
                try:
                    created = datetime.datetime.strptime(created, '%Y-%m-%d')
                except:
                    return None
        delta = datetime.datetime.utcnow() - created
        return delta.days
    except Exception:
        return None

def ip_asn_for_host(host):
    out = []
    try:
        ips = list({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception:
        ips = []
    for ip in ips:
        if IPWhois:
            try:
                r = IPWhois(ip).lookup_rdap(asn_methods=['whois'])
                out.append({'ip': ip, 'asn': r.get('asn'), 'asn_org': r.get('asn_description')})
            except Exception:
                out.append({'ip': ip})
        else:
            out.append({'ip': ip})
    return out

def lev_distance(a,b):
    if Levenshtein:
        try:
            return Levenshtein.distance(a.lower(), b.lower())
        except:
            pass
    a=a.lower(); b=b.lower()
    if len(a)==0 or len(b)==0:
        return max(len(a),len(b))
    minl = min(len(a), len(b))
    diff = sum(1 for i in range(minl) if a[i]!=b[i]) + abs(len(a)-len(b))
    return diff

def score_item(item, brand):
    url = item.get('url') or item.get('input') or item.get('target') or item.get('host') or ''
    title = item.get('title') or item.get('title_value') or ''
    status = item.get('status') or item.get('status_code') or item.get('statusCode') or None
    host = hostname_from_url(url)
    reg = tldextract.extract(host).registered_domain or host

    score = 0
    # brand token presence (but not exact match)
    if brand.lower() in reg.lower() and reg.lower() != brand.lower():
        score += 2

    domain_label = tldextract.extract(host).domain or host
    ld = lev_distance(domain_label, brand)
    if ld <= 2:
        score += 2

    low = (title + ' ' + url).lower()
    if any(k in low for k in PHISH_KEYWORDS):
        score += 1

    wdays = whois_age_days(reg)
    if wdays is None:
        score += 1
    else:
        if wdays < 90:
            score += 2
        elif wdays < 365:
            score += 1

    ipinfo = []
    try:
        ipinfo = ip_asn_for_host(host)
    except:
        ipinfo = []

    out = {
        'url': url,
        'hostname': host,
        'registered_domain': reg,
        'title': title,
        'status': status,
        'lev_distance': ld,
        'whois_days': wdays,
        'ip_asn': ipinfo,
        'suspicion_score': score
    }
    return out

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', '-i', required=True, help='probed.json (httpx json-lines) or probed.txt')
    p.add_argument('--brand', '-b', required=True, help='brand short name e.g., airtel')
    p.add_argument('--out', '-o', default=None, help='output json path')
    args = p.parse_args()

    inp = args.input
    if not os.path.exists(inp):
        print("Input not found:", inp, file=sys.stderr); sys.exit(2)

    items = []
    if inp.endswith('.json'):
        items = parse_httpx_json_lines(inp)
    else:
        items = parse_probed_txt(inp)

    results = []
    for it in items:
        try:
            r = score_item(it, args.brand)
            results.append(r)
        except Exception:
            continue

    out_json = args.out or os.path.join(os.path.dirname(inp),'scored.json')
    with open(out_json,'w',encoding='utf8') as fh:
        json.dump(results, fh, indent=2)

    csv_out = out_json.replace('.json','.csv')
    import csv
    with open(csv_out,'w',encoding='utf8',newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['hostname','registered_domain','url','status','title','lev_distance','whois_days','suspicion_score'])
        for r in results:
            w.writerow([r['hostname'], r['registered_domain'], r['url'], r['status'], r['title'], r['lev_distance'], r['whois_days'], r['suspicion_score']])

    print("Wrote", out_json, "and", csv_out)
    print("Top 20 suspicious (by suspicion_score):")
    top = sorted(results, key=lambda x: x['suspicion_score'], reverse=True)[:20]
    for t in top:
        print(t['suspicion_score'], t['hostname'], t['url'])

if __name__ == '__main__':
    main()
