const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");
const readline = require("readline");

async function run() {
  const outDir = "out";
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

  const results = [];

  const rl = readline.createInterface({
    input: fs.createReadStream("targets.txt"),
    crlfDelay: Infinity,
  });

  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });

  const page = await browser.newPage();

  let index = 0;
  for await (const url of rl) {
    index++;
    if (!url.trim()) continue;

    const safeName = url.replace(/[^a-z0-9]/gi, "_").toLowerCase();
    const outFile = path.join(outDir, `${safeName}.png`);

    try {
      await page.goto(url, { waitUntil: "load", timeout: 30000 });
      await page.screenshot({ path: outFile, fullPage: true });

      console.log(`[+] saved ${outFile}`);
      results.push({ url, status: "success", file: outFile });
    } catch (err) {
      console.log(`[!] fail ${url}: ${err.message}`);
      results.push({ url, status: "fail", error: err.message });
    }
  }

  await browser.close();

  // Save results as JSON + CSV
  fs.writeFileSync(
    path.join(outDir, "results.json"),
    JSON.stringify(results, null, 2)
  );

  const csv = [
    "url,status,file,error",
    ...results.map(
      (r) => `"${r.url}","${r.status}","${r.file || ""}","${r.error || ""}"`
    ),
  ].join("\n");
  fs.writeFileSync(path.join(outDir, "results.csv"), csv);

  console.log(`[+] Logs saved: ${path.join(outDir, "results.json")} and results.csv`);
}

run().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
