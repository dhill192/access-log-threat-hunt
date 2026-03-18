#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

function getArgs(argv) {
  const args = { input: null, output: "output", max: 5000 };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--in") args.input = argv[++i];
    if (argv[i] === "--out") args.output = argv[++i];
    if (argv[i] === "--max") args.max = Number(argv[++i]);
  }
  return args;
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function parseLine(line) {
  const regex =
    /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]+?)\s+HTTP\/[^"]+"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"/;
  const match = line.match(regex);
  if (!match) return null;

  return {
    ip: match[1],
    timestamp: match[2],
    method: match[3],
    request: match[4],
    status: Number(match[5]),
    referrer: match[7],
    userAgent: match[8],
    raw: line
  };
}

const detectors = [
  {
    id: "SQLI",
    severity: "high",
    regex: /\b(union\s+select|or\s+1=1|and\s+1=1|sleep\(|benchmark\(|information_schema)\b/i
  },
  {
    id: "XSS",
    severity: "high",
    regex: /(<script|%3cscript|onerror=|onload=|javascript:|alert\()/i
  },
  {
    id: "TRAVERSAL",
    severity: "high",
    regex: /(\.\.\/|\.\.\\|%2e%2e%2f)/i
  },
  {
    id: "SENSITIVE_FILES",
    severity: "medium",
    regex: /(\/\.env|\/\.git|\/wp-login\.php|\.bak|\.sql|config\.php)/i
  },
  {
    id: "SCANNER_UA",
    severity: "medium",
    regex: /\b(sqlmap|nikto|nmap|curl|wget|python-requests)\b/i
  }
];

function analyze(parsed) {
  const text = `${parsed.request} ${parsed.userAgent}`;
  const hits = [];

  for (const d of detectors) {
    if (d.regex.test(text)) {
      hits.push({ detector: d.id, severity: d.severity });
    }
  }

  if (hits.length === 0) return null;

  return {
    ip: parsed.ip,
    timestamp: parsed.timestamp,
    request: parsed.request,
    hits
  };
}

// --- MAIN EXECUTION ---

const args = getArgs(process.argv);

if (!args.input) {
  console.error("❌ Please provide input file: --in <logfile>");
  process.exit(1);
}

ensureDir(args.output);

const lines = fs.readFileSync(args.input, "utf-8").split("\n").slice(0, args.max);

const alerts = [];
const ipCounts = {};

for (const line of lines) {
  const parsed = parseLine(line);
  if (!parsed) continue;

  // Track IP counts (for brute-force style detection later)
  ipCounts[parsed.ip] = (ipCounts[parsed.ip] || 0) + 1;

  const result = analyze(parsed);
  if (result) alerts.push(result);
}

// Detect high-volume IPs
const suspiciousIPs = [];
for (const ip in ipCounts) {
  if (ipCounts[ip] > 100) {
    suspiciousIPs.push({ ip, count: ipCounts[ip] });
  }
}

// --- OUTPUT ---

console.log("\n🚨 DETECTED THREATS:");
console.log(alerts);

console.log("\n🚨 HIGH VOLUME IPS:");
console.log(suspiciousIPs);

// Save results
fs.writeFileSync(
  path.join(args.output, "alerts.json"),
  JSON.stringify(alerts, null, 2)
);

fs.writeFileSync(
  path.join(args.output, "ip_summary.json"),
  JSON.stringify(ipCounts, null, 2)
);

console.log("\n✅ Analysis complete. Results saved to output/");
