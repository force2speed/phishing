#!/usr/bin/env python3
import asyncio, sys, os
from playwright.async_api import async_playwright

async def main():
    outdir = "/app/out"
    os.makedirs(outdir, exist_ok=True)
    targets_file = "/app/targets.txt"
    if not os.path.exists(targets_file):
        print("No targets.txt provided", file=sys.stderr)
        sys.exit(1)

    with open(targets_file) as f:
        urls = [line.strip() for line in f if line.strip()]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        for i, url in enumerate(urls, 1):
            try:
                page = await context.new_page()
                await page.goto(url, timeout=15000)
                fname = os.path.join(outdir, f"shot_{i}.png")
                await page.screenshot(path=fname, full_page=True)
                print(f"[+] saved {fname}")
                await page.close()
            except Exception as e:
                print(f"[!] fail {url}: {e}")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
