#!/usr/bin/env python3
# snapworker.py — Playwright worker that saves screenshots named by sanitized URL/hostname
import asyncio, sys, os, json, csv, time
from urllib.parse import urlparse
from playwright.async_api import async_playwright

def sanitize_filename(s: str, maxlen: int = 200) -> str:
    if not s:
        return "site"
    safe = "".join([c if c.isalnum() else "_" for c in s])
    safe = "_".join([p for p in safe.split("_") if p])  # collapse underscores
    if len(safe) > maxlen:
        safe = safe[:maxlen]
    return safe.lower()

async def capture_one(page, url, outdir, timeout=30000):
    """Try to load url and screenshot; returns (status, filename, error)"""
    filename = ""
    try:
        await page.goto(url, timeout=timeout, wait_until="load")
        # remove scripts (optional)
        try:
            await page.evaluate("() => { Array.from(document.querySelectorAll('script')).forEach(s=>s.remove()); }")
        except Exception:
            pass

        # 🔑 NEW: use only the hostname for filenames
        host = urlparse(url).hostname or url
        safe = sanitize_filename(host)
        filename = f"{safe}.png"

        path = os.path.join(outdir, filename)
        if os.path.exists(path):
            ts = str(int(time.time()))[-6:]
            filename = f"{safe}_{ts}.png"
            path = os.path.join(outdir, filename)

        await page.screenshot(path=path, full_page=True)
        return "success", filename, ""
    except Exception as e:
        return "fail", "", str(e)

async def main():
    outdir = "/app/out"
    targets_file = "/app/targets.txt"
    os.makedirs(outdir, exist_ok=True)

    if not os.path.exists(targets_file):
        print("No targets.txt provided at /app/targets.txt", file=sys.stderr)
        sys.exit(1)

    # read targets preserving order
    with open(targets_file, "r", encoding="utf8") as fh:
        urls = [line.strip() for line in fh if line.strip()]

    results = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # ignore HTTPS errors in context so cert problems don't block screenshots
        context = await browser.new_context(ignore_https_errors=True, viewport={"width":1280,"height":800})
        page = await context.new_page()

        for i, raw in enumerate(urls, 1):
            url = raw
            if not (url.startswith("http://") or url.startswith("https://")):
                # default to https first
                url = "https://" + url

            print(f"[{i}/{len(urls)}] try {url}")
            status, fname, err = await capture_one(page, url, outdir, timeout=30000)
            if status == "fail":
                # fallback: toggle scheme and retry once
                try:
                    alt = ("http://" if url.startswith("https://") else "https://") + url.split("://",1)[1]
                    print(f"   fallback to {alt}")
                    status, fname, err = await capture_one(page, alt, outdir, timeout=20000)
                    if status == "success":
                        url = alt
                except Exception:
                    pass

            if status == "success":
                print(f"[+] saved {fname}")
            else:
                print(f"[!] fail {raw}: {err}")

            results.append({
                "input": raw,
                "used_url": url,
                "status": status,
                "file": fname,
                "error": err
            })

            # small delay to avoid hammering (tweak if needed)
            await asyncio.sleep(0.15)

        await browser.close()

    # write logs
    json_path = os.path.join(outdir, "results.json")
    csv_path = os.path.join(outdir, "results.csv")
    with open(json_path, "w", encoding="utf8") as jh:
        json.dump(results, jh, indent=2)
    with open(csv_path, "w", encoding="utf8", newline="") as ch:
        writer = csv.writer(ch)
        writer.writerow(["input","used_url","status","file","error"])
        for r in results:
            writer.writerow([r["input"], r["used_url"], r["status"], r["file"], r["error"]])

    print(f"[+] Done. logs: {json_path} , {csv_path}")

if __name__ == "__main__":
    asyncio.run(main())
