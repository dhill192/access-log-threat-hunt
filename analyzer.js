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
    time: parsed.timestamp,
    request: parsed.request,
    status: parsed.status,
    userAgent: parsed.userAgent,
    hits
  };
}

function main() {
  const args = getArgs(process.argv);
  if (!args.input) {
    console.log("Usage: node analyzer.js --in access.log");
    process.exit(1);
  }

  if (!fs.existsSync(args.input)) {
    console.error("Input file not found.");
    process.exit(1);
  }

  ensureDir(args.output);

  const lines = fs.readFileSync(args.input, "utf8").split(/\r?\n/);

  const flagged = [];
  const stats = {
    totalLines: 0,
    flagged: 0,
    byDetector: {},
    bySeverity: {}
  };

  for (const line of lines) {
    if (!line.trim()) continue;
    stats.totalLines++;

    const parsed = parseLine(line);
    if (!parsed) continue;

    const result = analyze(parsed);
    if (result) {
      stats.flagged++;

      for (const h of result.hits) {
        stats.byDetector[h.detector] = (stats.byDetector[h.detector] || 0) + 1;
        stats.bySeverity[h.severity] = (stats.bySeverity[h.severity] || 0) + 1;
      }

      if (flagged.length < args.max) flagged.push(result);
    }
  }

  fs.writeFileSync(
    path.join(args.output, "flagged.json"),
    JSON.stringify(flagged, null, 2)
  );

  fs.writeFileSync(
    path.join(args.output, "summary.json"),
    JSON.stringify(stats, null, 2)
  );

  console.log("Analysis complete.");
  console.log(stats);
}

main();
