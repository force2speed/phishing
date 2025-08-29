const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const puppeteer = require("puppeteer");
const whois = require("whois");
const { crawlPage } = require("./crawl.js");   // ✅ bring back your crawler
const { printReport } = require("./report.js");

// Helper: WHOIS lookup with fallback
function getWhois(domain) {
  return new Promise((resolve) => {
    whois.lookup(domain, (err, data) => {
      if (err) {
        resolve({ status: "failed", reason: err.message });
      } else {
        resolve({ raw: data });
      }
    });
  });
}

// Helper: Fallback registry info if WHOIS fails
function getRegistryInfo(domain) {
  if (domain.endsWith(".dev")) {
    return { registry: "Google Registry", note: ".dev domains use Google WHOIS which blocks queries" };
  }
  if (domain.endsWith(".app")) {
    return { registry: "Google Registry", note: ".app domains also block WHOIS queries" };
  }
  if (domain.endsWith(".xyz")) {
    return { registry: "XYZ Registry", note: "Limited WHOIS data available" };
  }
  return { registry: "Unknown", note: "No fallback available" };
}

async function main() {
  if (process.argv.length < 3) {
    console.log("no website provided");
    process.exit(1);
  }
  if (process.argv.length > 3) {
    console.log("Too many command line arguments");
    process.exit(1);
  }

  const baseURL = process.argv[2];
  const targetOrg = "Example Organisation"; // 🔹 edit as needed
  const sourceOfDetection = "Custom WebCrawler";

  console.log(`Starting crawl of ${baseURL}`);

  // ✅ Run your crawler
  const pages = await crawlPage(baseURL, baseURL, {});
  printReport(pages);

  // Screenshot folder
  const screenshotDir = path.join(__dirname, "screenshots");
  if (!fs.existsSync(screenshotDir)) fs.mkdirSync(screenshotDir);

  // Puppeteer setup
  const browser = await puppeteer.launch({
    executablePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", // adjust path if Chrome is elsewhere
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  });
  const page = await browser.newPage();

  let screenshotPath;
  let dateOfPost = "Unknown";

  try {
    console.log(`Visiting main domain: ${baseURL}`);
    await page.goto(baseURL, { waitUntil: "networkidle2", timeout: 60000 });

    screenshotPath = path.join(screenshotDir, "main_domain.png");
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`✅ Screenshot saved: ${screenshotPath}`);

    // Try to extract <meta property="article:published_time">
    dateOfPost = await page.$eval(
      'meta[property="article:published_time"]',
      el => el.content
    ).catch(() => "Not found");
  } catch (err) {
    console.error(`❌ Error visiting ${baseURL}:`, err.message);
  }
  await browser.close();

  // Domain parsing
  const urlObj = new URL(baseURL);
  const domain = urlObj.hostname;

  // WHOIS
  let whoisData = await getWhois(domain);
  if (whoisData.status === "failed") {
    whoisData = {
      ...whoisData,
      ...getRegistryInfo(domain)
    };
  }

  // Hosting (IP address)
  let hostingData = {};
  try {
    hostingData = await dns.lookup(domain);
  } catch (err) {
    hostingData = { error: `DNS lookup failed: ${err.message}` };
  }

  // Final report object
  const report = {
    organisation: targetOrg,
    domain: domain,
    detectionTime: new Date().toISOString(),
    screenshot: screenshotPath,
    whois: whoisData,
    hosting: hostingData,
    source: sourceOfDetection,
    postDate: dateOfPost,
    crawledPages: Object.keys(pages)   // ✅ include all pages found in crawl
  };

  // Save report.json
  fs.writeFileSync("report.json", JSON.stringify(report, null, 2));
  console.log("✅ Report saved to report.json");
}

main();
