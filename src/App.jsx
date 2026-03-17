import { useState, useCallback, useRef, useEffect } from "react";

const SEVERITY = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const SEV_LABELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SEV_COLORS = ["#6ee7b7", "#a5b4fc", "#fbbf24", "#fb923c", "#ef4444"];

// ─── Analysis Engine ──────────────────────────────────────────
const PATTERNS = {
  secrets: [
    { name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/g, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
    { name: "AWS Secret Key", regex: /(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
    { name: "Generic API Key", regex: /(?:api[_-]?key|apikey|api_secret|access_token|auth_token|secret_key)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]?/gi, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
    { name: "Google API Key", regex: /AIza[0-9A-Za-z_-]{35}/g, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
    { name: "Stripe Key", regex: /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}/g, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
    { name: "GitHub Token", regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
    { name: "Slack Token", regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, severity: SEVERITY.HIGH, category: "Secrets & Keys" },
    { name: "JWT Token", regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: SEVERITY.HIGH, category: "Secrets & Keys" },
    { name: "Private Key Block", regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
    { name: "Bearer Token", regex: /['"]Bearer\s+[A-Za-z0-9_\-.]{20,}['"]/g, severity: SEVERITY.HIGH, category: "Secrets & Keys" },
    { name: "Basic Auth Credentials", regex: /['"]Basic\s+[A-Za-z0-9+/=]{10,}['"]/g, severity: SEVERITY.HIGH, category: "Secrets & Keys" },
    { name: "Password in Code", regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
    { name: "Database Connection String", regex: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+/gi, severity: SEVERITY.CRITICAL, category: "Secrets & Keys" },
  ],
  pii: [
    { name: "Email Address", regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: SEVERITY.MEDIUM, category: "PII Exposure" },
    { name: "Phone Number (US)", regex: /(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, severity: SEVERITY.MEDIUM, category: "PII Exposure" },
    { name: "Phone Number (Intl)", regex: /\+\d{1,3}[-.\s]?\d{4,14}/g, severity: SEVERITY.MEDIUM, category: "PII Exposure" },
    { name: "SSN Pattern", regex: /\b\d{3}-\d{2}-\d{4}\b/g, severity: SEVERITY.CRITICAL, category: "PII Exposure" },
    { name: "Credit Card Pattern", regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g, severity: SEVERITY.CRITICAL, category: "PII Exposure" },
    { name: "IP Address (Private)", regex: /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g, severity: SEVERITY.MEDIUM, category: "PII Exposure" },
  ],
  urls: [
    { name: "Internal/Private URL", regex: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?[^\s'"<]*/g, severity: SEVERITY.HIGH, category: "URL & Endpoint Exposure" },
    { name: "Staging/Dev URL", regex: /https?:\/\/(?:staging|dev|test|uat|qa|sandbox|internal|preprod|beta)\.[^\s'"<]+/gi, severity: SEVERITY.HIGH, category: "URL & Endpoint Exposure" },
    { name: "Private API Endpoint", regex: /['"]\/(?:api\/(?:v\d+\/)?(?:internal|admin|private|debug|test|dev))[^\s'"<]*/gi, severity: SEVERITY.HIGH, category: "URL & Endpoint Exposure" },
    { name: "Hidden Admin Path", regex: /['"]\/(?:admin|dashboard|management|_admin|wp-admin|phpmyadmin|cpanel|cms|backoffice|panel)[^\s'"<]*/gi, severity: SEVERITY.HIGH, category: "URL & Endpoint Exposure" },
    { name: "Test Endpoint", regex: /['"]\/(?:test|debug|health|status|ping|info|phpinfo|env|config|setup)[^\s'"<]*/gi, severity: SEVERITY.MEDIUM, category: "URL & Endpoint Exposure" },
    { name: "GraphQL Endpoint", regex: /['"]\/graphql[^\s'"<]*/gi, severity: SEVERITY.MEDIUM, category: "URL & Endpoint Exposure" },
  ],
  xss: [
    { name: "eval() Usage", regex: /\beval\s*\(/g, severity: SEVERITY.CRITICAL, category: "XSS & Injection" },
    { name: "innerHTML Assignment", regex: /\.innerHTML\s*[+]?=/g, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "outerHTML Assignment", regex: /\.outerHTML\s*[+]?=/g, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "document.write()", regex: /document\.write(?:ln)?\s*\(/g, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "Inline Event Handler", regex: /\bon(?:click|load|error|mouseover|focus|blur|submit|change|input|keyup|keydown)\s*=\s*['"][^'"]*['"]/gi, severity: SEVERITY.MEDIUM, category: "XSS & Injection" },
    { name: "javascript: Protocol", regex: /javascript\s*:/gi, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "data: URI in src/href", regex: /(?:src|href)\s*=\s*['"]data:/gi, severity: SEVERITY.MEDIUM, category: "XSS & Injection" },
    { name: "Function() Constructor", regex: /new\s+Function\s*\(/g, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "setTimeout/setInterval with String", regex: /(?:setTimeout|setInterval)\s*\(\s*['"`]/g, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "DOM Insertion (insertAdjacentHTML)", regex: /\.insertAdjacentHTML\s*\(/g, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "Unescaped Template Literal in DOM", regex: /\.innerHTML\s*=\s*`[^`]*\$\{/g, severity: SEVERITY.CRITICAL, category: "XSS & Injection" },
    { name: "Potential XSS Payload", regex: /<script[^>]*>[\s\S]*?<\/script>/gi, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "SVG onload XSS", regex: /<svg[^>]*\bonload\s*=/gi, severity: SEVERITY.HIGH, category: "XSS & Injection" },
    { name: "img onerror XSS", regex: /<img[^>]*\bonerror\s*=/gi, severity: SEVERITY.HIGH, category: "XSS & Injection" },
  ],
  forms: [
    { name: "Password Field on Page", regex: /<input[^>]*type\s*=\s*['"]password['"]/gi, severity: SEVERITY.MEDIUM, category: "Form Security" },
    { name: "Form with HTTP Action", regex: /<form[^>]*action\s*=\s*['"]http:\/\//gi, severity: SEVERITY.HIGH, category: "Form Security" },
    { name: "Form Missing Action", regex: /<form(?![^>]*action\s*=)[^>]*>/gi, severity: SEVERITY.LOW, category: "Form Security" },
    { name: "Autocomplete Not Disabled (Sensitive)", regex: /<input[^>]*type\s*=\s*['"](?:password|credit)['"]((?!autocomplete\s*=\s*['"]off['"])[^>])*>/gi, severity: SEVERITY.LOW, category: "Form Security" },
  ],
  csrf: [
    { name: "Form Without CSRF Token", regex: /<form[^>]*method\s*=\s*['"]post['"][^>]*>(?:(?!csrf|_token|authenticity_token|__RequestVerificationToken)[\s\S])*?<\/form>/gi, severity: SEVERITY.HIGH, category: "CSRF Protection" },
  ],
  mixedContent: [
    { name: "HTTP Script on HTTPS Page", regex: /<script[^>]*src\s*=\s*['"]http:\/\//gi, severity: SEVERITY.HIGH, category: "Mixed Content" },
    { name: "HTTP Stylesheet", regex: /<link[^>]*href\s*=\s*['"]http:\/\//gi, severity: SEVERITY.MEDIUM, category: "Mixed Content" },
    { name: "HTTP Image", regex: /<img[^>]*src\s*=\s*['"]http:\/\//gi, severity: SEVERITY.LOW, category: "Mixed Content" },
    { name: "HTTP iframe", regex: /<iframe[^>]*src\s*=\s*['"]http:\/\//gi, severity: SEVERITY.HIGH, category: "Mixed Content" },
  ],
  thirdParty: [
    { name: "External Script", regex: /<script[^>]*src\s*=\s*['"]https?:\/\/(?!(?:cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|ajax\.googleapis\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com))[^'"]+['"]/gi, severity: SEVERITY.MEDIUM, category: "Third-Party & Supply Chain" },
    { name: "Tracking Pixel", regex: /<img[^>]*src\s*=\s*['"][^'"]*(?:pixel|track|beacon|analytics|collect|log)[^'"]*['"][^>]*(?:width\s*=\s*['"]1['"]|height\s*=\s*['"]1['"]|style\s*=\s*['"][^'"]*display\s*:\s*none)/gi, severity: SEVERITY.MEDIUM, category: "Third-Party & Supply Chain" },
    { name: "Google Analytics", regex: /(?:google-analytics\.com|googletagmanager\.com|gtag|ga\s*\(\s*['"]send['"])/g, severity: SEVERITY.INFO, category: "Third-Party & Supply Chain" },
    { name: "Facebook Pixel", regex: /(?:connect\.facebook\.net|fbq\s*\()/g, severity: SEVERITY.INFO, category: "Third-Party & Supply Chain" },
    { name: "Integrity Missing on External Script", regex: /<script[^>]*src\s*=\s*['"]https?:\/\/[^'"]+['"](?![^>]*integrity\s*=)[^>]*>/gi, severity: SEVERITY.MEDIUM, category: "Third-Party & Supply Chain" },
  ],
  headers: [
    { name: "Missing CSP Meta Tag", test: (c) => !/<meta[^>]*http-equiv\s*=\s*['"]Content-Security-Policy['"]/i.test(c), severity: SEVERITY.HIGH, category: "Security Headers", single: true },
    { name: "Missing Referrer Policy", test: (c) => !/<meta[^>]*name\s*=\s*['"]referrer['"]/i.test(c) && !/Referrer-Policy/i.test(c), severity: SEVERITY.MEDIUM, category: "Security Headers", single: true },
    { name: "Missing X-Frame-Options (Clickjacking)", test: (c) => !/<meta[^>]*http-equiv\s*=\s*['"]X-Frame-Options['"]/i.test(c), severity: SEVERITY.MEDIUM, category: "Security Headers", single: true },
    { name: "Missing X-Content-Type-Options", test: (c) => !/<meta[^>]*http-equiv\s*=\s*['"]X-Content-Type-Options['"]/i.test(c), severity: SEVERITY.LOW, category: "Security Headers", single: true },
    { name: "Weak CSP (unsafe-inline)", regex: /Content-Security-Policy[^'"]*unsafe-inline/gi, severity: SEVERITY.HIGH, category: "Security Headers" },
    { name: "Weak CSP (unsafe-eval)", regex: /Content-Security-Policy[^'"]*unsafe-eval/gi, severity: SEVERITY.HIGH, category: "Security Headers" },
    { name: "Weak CSP (wildcard)", regex: /Content-Security-Policy[^'"]*\s\*\s/gi, severity: SEVERITY.HIGH, category: "Security Headers" },
  ],
  debug: [
    { name: "Console.log Statement", regex: /console\.(?:log|debug|info|warn|error|trace|table|dir)\s*\(/g, severity: SEVERITY.LOW, category: "Debug & Dev Artifacts" },
    { name: "debugger Statement", regex: /\bdebugger\b/g, severity: SEVERITY.MEDIUM, category: "Debug & Dev Artifacts" },
    { name: "TODO/FIXME/HACK Comment", regex: /(?:\/\/|\/\*|<!--)\s*(?:TODO|FIXME|HACK|XXX|BUG|TEMP|TEMPORARY)\b[^\n]*/gi, severity: SEVERITY.LOW, category: "Debug & Dev Artifacts" },
    { name: "Commented Credentials", regex: /(?:\/\/|\/\*|<!--)[^\n]*(?:password|secret|token|key)\s*[:=]/gi, severity: SEVERITY.HIGH, category: "Debug & Dev Artifacts" },
    { name: "Source Map Reference", regex: /\/\/[#@]\s*sourceMappingURL\s*=/g, severity: SEVERITY.LOW, category: "Debug & Dev Artifacts" },
    { name: "Stack Trace Exposure", regex: /(?:at\s+\w+\s+\([\w/.]+:\d+:\d+\)|Error:.*\n\s+at\s)/g, severity: SEVERITY.MEDIUM, category: "Debug & Dev Artifacts" },
    { name: "Version/Build Info Exposed", regex: /(?:version|build|commit|rev)\s*[:=]\s*['"][^'"]+['"]/gi, severity: SEVERITY.LOW, category: "Debug & Dev Artifacts" },
  ],
  comments: [
    { name: "HTML Comment with Internal Info", regex: /<!--[\s\S]*?(?:internal|private|secret|todo|fixme|hack|password|credentials|server|database|endpoint|api|config)[\s\S]*?-->/gi, severity: SEVERITY.MEDIUM, category: "Information Leakage" },
    { name: "JS Comment with Sensitive Info", regex: /\/\/[^\n]*(?:internal|private|secret|password|credentials|server|database|config)[^\n]*/gi, severity: SEVERITY.MEDIUM, category: "Information Leakage" },
    { name: "Block Comment with Sensitive Info", regex: /\/\*[\s\S]*?(?:internal|private|secret|password|credentials|server|database)[\s\S]*?\*\//gi, severity: SEVERITY.MEDIUM, category: "Information Leakage" },
  ],
  libraries: [
    { name: "jQuery (Check Version)", regex: /jquery[.-](\d+\.\d+\.\d+)/gi, severity: SEVERITY.INFO, category: "Outdated Libraries", extract: true },
    { name: "Bootstrap (Check Version)", regex: /bootstrap[.-](\d+\.\d+\.\d+)/gi, severity: SEVERITY.INFO, category: "Outdated Libraries", extract: true },
    { name: "Angular.js (1.x - EOL)", regex: /angular[.-]1\.\d+/gi, severity: SEVERITY.HIGH, category: "Outdated Libraries" },
    { name: "Moment.js (Deprecated)", regex: /moment(?:\.min)?\.js/gi, severity: SEVERITY.LOW, category: "Outdated Libraries" },
  ],
};

function getLineNumber(content, index) {
  return content.substring(0, index).split("\n").length;
}

function analyzeContent(content, fileName) {
  const findings = [];
  for (const group of Object.values(PATTERNS)) {
    for (const p of group) {
      if (p.single && p.test) {
        if (p.test(content)) {
          findings.push({ rule: p.name, severity: p.severity, category: p.category, file: fileName, line: "-", snippet: "(entire file checked)" });
        }
      } else if (p.regex) {
        p.regex.lastIndex = 0;
        let m;
        const seen = new Set();
        while ((m = p.regex.exec(content)) !== null) {
          const snippet = m[0].length > 120 ? m[0].slice(0, 117) + "..." : m[0];
          const key = `${p.name}:${snippet}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({ rule: p.name, severity: p.severity, category: p.category, file: fileName, line: getLineNumber(content, m.index), snippet });
        }
      }
    }
  }
  return findings;
}

// ─── UI Components ────────────────────────────────────────────
const SeverityBadge = ({ severity }) => (
  <span style={{ display: "inline-block", padding: "2px 10px", borderRadius: 3, fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: "#0a0a0f", background: SEV_COLORS[severity], fontFamily: "'JetBrains Mono', monospace" }}>
    {SEV_LABELS[severity]}
  </span>
);

const StatCard = ({ label, value, color, icon }) => (
  <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, padding: "18px 20px", flex: 1, minWidth: 140 }}>
    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>{icon} {label}</div>
    <div style={{ fontSize: 28, fontWeight: 800, color, fontFamily: "'Space Grotesk', sans-serif" }}>{value}</div>
  </div>
);

const RiskMeter = ({ score }) => {
  const label = score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 35 ? "MODERATE" : score >= 15 ? "LOW" : "CLEAN";
  const color = score >= 80 ? "#ef4444" : score >= 60 ? "#fb923c" : score >= 35 ? "#fbbf24" : score >= 15 ? "#a5b4fc" : "#6ee7b7";
  return (
    <div style={{ textAlign: "center", padding: "24px 0" }}>
      <div style={{ position: "relative", width: 180, height: 90, margin: "0 auto" }}>
        <svg viewBox="0 0 180 90" width={180} height={90}>
          <path d="M 10 85 A 80 80 0 0 1 170 85" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={10} strokeLinecap="round" />
          <path d="M 10 85 A 80 80 0 0 1 170 85" fill="none" stroke={color} strokeWidth={10} strokeLinecap="round"
            strokeDasharray={`${(score / 100) * 251.2} 251.2`}
            style={{ filter: `drop-shadow(0 0 8px ${color}80)`, transition: "stroke-dasharray 1s ease" }} />
        </svg>
        <div style={{ position: "absolute", bottom: 0, left: "50%", transform: "translateX(-50%)", textAlign: "center" }}>
          <div style={{ fontSize: 32, fontWeight: 800, color, fontFamily: "'Space Grotesk', sans-serif" }}>{score}</div>
        </div>
      </div>
      <div style={{ fontSize: 12, color, fontWeight: 700, letterSpacing: "0.15em", marginTop: 8, fontFamily: "'JetBrains Mono', monospace" }}>RISK: {label}</div>
    </div>
  );
};

export default function CyberSecAnalyzer() {
  const [files, setFiles] = useState([]);
  const [findings, setFindings] = useState([]);
  const [analyzed, setAnalyzed] = useState(false);
  const [activeCategory, setActiveCategory] = useState("All");
  const [activeSeverity, setActiveSeverity] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [sortBy, setSortBy] = useState("severity");
  const dropRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);

  const handleFiles = useCallback((fileList) => {
    const valid = Array.from(fileList).filter(f => /\.(html?|js|jsx|ts|tsx|vue|svelte|php|css)$/i.test(f.name));
    if (valid.length === 0) return;
    setFiles(prev => [...prev, ...valid]);
    setAnalyzed(false);
    setFindings([]);
  }, []);

  const runAnalysis = useCallback(async () => {
    setScanning(true);
    setScanProgress(0);
    const allFindings = [];
    for (let i = 0; i < files.length; i++) {
      const text = await files[i].text();
      const f = analyzeContent(text, files[i].name);
      allFindings.push(...f);
      setScanProgress(Math.round(((i + 1) / files.length) * 100));
      await new Promise(r => setTimeout(r, 120));
    }
    setFindings(allFindings);
    setAnalyzed(true);
    setScanning(false);
  }, [files]);

  const riskScore = analyzed ? Math.min(100, Math.round(
    findings.reduce((s, f) => s + [0.5, 1, 3, 7, 15][f.severity], 0)
  )) : 0;

  const categories = ["All", ...Array.from(new Set(findings.map(f => f.category)))];
  const filtered = findings.filter(f =>
    (activeCategory === "All" || f.category === activeCategory) &&
    (activeSeverity === null || f.severity === activeSeverity)
  ).sort((a, b) => sortBy === "severity" ? b.severity - a.severity : a.file.localeCompare(b.file));

  const counts = [0, 1, 2, 3, 4].map(s => findings.filter(f => f.severity === s).length);

  const reset = () => { setFiles([]); setFindings([]); setAnalyzed(false); setActiveCategory("All"); setActiveSeverity(null); };

  return (
    <div style={{ minHeight: "100vh", background: "#08080c", color: "#e2e2e8", fontFamily: "'Inter', 'Segoe UI', sans-serif" }}>
      <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@400;700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet" />

      {/* Header */}
      <header style={{ borderBottom: "1px solid rgba(255,255,255,0.06)", padding: "16px 24px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 8, background: "linear-gradient(135deg, #ef4444, #f97316)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>🛡</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", letterSpacing: "-0.02em" }}>SENTINEL</div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em" }}>STATIC SECURITY ANALYZER</div>
          </div>
        </div>
        {analyzed && (
          <button onClick={reset} style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", color: "#e2e2e8", padding: "8px 16px", borderRadius: 6, cursor: "pointer", fontSize: 12, fontFamily: "'JetBrains Mono', monospace" }}>
            ↻ New Scan
          </button>
        )}
      </header>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "24px 20px" }}>
        {/* Upload Area */}
        {!analyzed && !scanning && (
          <div
            ref={dropRef}
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={e => { e.preventDefault(); setDragOver(false); handleFiles(e.dataTransfer.files); }}
            style={{
              border: `2px dashed ${dragOver ? "#f97316" : "rgba(255,255,255,0.12)"}`,
              borderRadius: 12,
              padding: "48px 24px",
              textAlign: "center",
              background: dragOver ? "rgba(249,115,22,0.05)" : "rgba(255,255,255,0.02)",
              transition: "all 0.2s",
              cursor: "pointer",
              marginBottom: 24,
            }}
            onClick={() => { const i = document.createElement("input"); i.type = "file"; i.multiple = true; i.accept = ".html,.htm,.js,.jsx,.ts,.tsx,.vue,.svelte,.php,.css"; i.onchange = e => handleFiles(e.target.files); i.click(); }}
          >
            <div style={{ fontSize: 40, marginBottom: 12 }}>⬆</div>
            <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 6 }}>Drop files here or click to browse</div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", fontFamily: "'JetBrains Mono', monospace" }}>
              .html .js .jsx .ts .tsx .vue .svelte .php .css
            </div>
          </div>
        )}

        {/* File List */}
        {files.length > 0 && !analyzed && !scanning && (
          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 10, fontFamily: "'JetBrains Mono', monospace" }}>
              {files.length} file{files.length > 1 ? "s" : ""} queued
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 20 }}>
              {files.map((f, i) => (
                <span key={i} style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 4, padding: "4px 10px", fontSize: 12, fontFamily: "'JetBrains Mono', monospace", display: "flex", alignItems: "center", gap: 6 }}>
                  {f.name}
                  <span onClick={e => { e.stopPropagation(); setFiles(prev => prev.filter((_, j) => j !== i)); }} style={{ cursor: "pointer", opacity: 0.4, fontSize: 14 }}>×</span>
                </span>
              ))}
            </div>
            <button onClick={runAnalysis} style={{ background: "linear-gradient(135deg, #ef4444, #f97316)", border: "none", color: "#fff", padding: "12px 32px", borderRadius: 8, fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: "'Space Grotesk', sans-serif", letterSpacing: "0.02em" }}>
              ▶ Run Security Scan
            </button>
          </div>
        )}

        {/* Scanning Animation */}
        {scanning && (
          <div style={{ textAlign: "center", padding: "60px 0" }}>
            <div style={{ fontSize: 13, color: "#f97316", fontFamily: "'JetBrains Mono', monospace", marginBottom: 16, letterSpacing: "0.1em" }}>
              SCANNING... {scanProgress}%
            </div>
            <div style={{ width: 300, height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, margin: "0 auto", overflow: "hidden" }}>
              <div style={{ width: `${scanProgress}%`, height: "100%", background: "linear-gradient(90deg, #ef4444, #f97316)", borderRadius: 2, transition: "width 0.3s ease" }} />
            </div>
          </div>
        )}

        {/* Results */}
        {analyzed && (
          <>
            {/* Overview */}
            <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 24 }}>
              <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, padding: "12px 20px", minWidth: 200 }}>
                <RiskMeter score={riskScore} />
              </div>
              <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 10, minWidth: 280 }}>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <StatCard label="Total Findings" value={findings.length} color="#e2e2e8" icon="⚡" />
                  <StatCard label="Files Scanned" value={files.length} color="#a5b4fc" icon="📄" />
                </div>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <StatCard label="Critical" value={counts[4]} color="#ef4444" icon="🔴" />
                  <StatCard label="High" value={counts[3]} color="#fb923c" icon="🟠" />
                  <StatCard label="Medium" value={counts[2]} color="#fbbf24" icon="🟡" />
                  <StatCard label="Low/Info" value={counts[1] + counts[0]} color="#6ee7b7" icon="🟢" />
                </div>
              </div>
            </div>

            {/* Filters */}
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              {categories.map(c => (
                <button key={c} onClick={() => setActiveCategory(c)} style={{
                  background: activeCategory === c ? "rgba(249,115,22,0.15)" : "rgba(255,255,255,0.03)",
                  border: `1px solid ${activeCategory === c ? "rgba(249,115,22,0.4)" : "rgba(255,255,255,0.08)"}`,
                  color: activeCategory === c ? "#f97316" : "rgba(255,255,255,0.5)",
                  padding: "5px 12px", borderRadius: 4, fontSize: 11, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace",
                }}>
                  {c}
                </button>
              ))}
            </div>
            <div style={{ display: "flex", gap: 6, marginBottom: 16, alignItems: "center" }}>
              <span style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", fontFamily: "'JetBrains Mono', monospace", marginRight: 4 }}>Severity:</span>
              {[4, 3, 2, 1, 0].map(s => (
                <button key={s} onClick={() => setActiveSeverity(activeSeverity === s ? null : s)} style={{
                  background: activeSeverity === s ? `${SEV_COLORS[s]}22` : "transparent",
                  border: `1px solid ${activeSeverity === s ? SEV_COLORS[s] : "rgba(255,255,255,0.08)"}`,
                  color: activeSeverity === s ? SEV_COLORS[s] : "rgba(255,255,255,0.4)",
                  padding: "3px 8px", borderRadius: 3, fontSize: 10, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace",
                }}>
                  {SEV_LABELS[s]}
                </button>
              ))}
              <div style={{ marginLeft: "auto" }}>
                <button onClick={() => setSortBy(sortBy === "severity" ? "file" : "severity")} style={{
                  background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
                  color: "rgba(255,255,255,0.5)", padding: "3px 10px", borderRadius: 3, fontSize: 10, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace",
                }}>
                  Sort: {sortBy === "severity" ? "Severity ↓" : "File A→Z"}
                </button>
              </div>
            </div>

            {/* Findings Table */}
            {filtered.length === 0 ? (
              <div style={{ textAlign: "center", padding: 40, color: "rgba(255,255,255,0.3)", fontSize: 13 }}>No findings match your filters.</div>
            ) : (
              <div style={{ border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, overflow: "hidden" }}>
                <div style={{ display: "grid", gridTemplateColumns: "90px 1fr 1fr 60px", padding: "10px 16px", background: "rgba(255,255,255,0.03)", fontSize: 10, color: "rgba(255,255,255,0.35)", textTransform: "uppercase", letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                  <div>Severity</div><div>Finding</div><div>File</div><div>Line</div>
                </div>
                <div style={{ maxHeight: 500, overflowY: "auto" }}>
                  {filtered.map((f, i) => (
                    <div key={i}>
                      <div
                        onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                        style={{
                          display: "grid", gridTemplateColumns: "90px 1fr 1fr 60px", padding: "10px 16px", fontSize: 12,
                          borderBottom: "1px solid rgba(255,255,255,0.04)", cursor: "pointer",
                          background: expandedRow === i ? "rgba(255,255,255,0.04)" : "transparent",
                          transition: "background 0.15s",
                        }}
                        onMouseEnter={e => { if (expandedRow !== i) e.currentTarget.style.background = "rgba(255,255,255,0.02)"; }}
                        onMouseLeave={e => { if (expandedRow !== i) e.currentTarget.style.background = "transparent"; }}
                      >
                        <div><SeverityBadge severity={f.severity} /></div>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "rgba(255,255,255,0.8)" }}>{f.rule}</div>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "rgba(255,255,255,0.5)" }}>{f.file}</div>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "rgba(255,255,255,0.4)" }}>{f.line}</div>
                      </div>
                      {expandedRow === i && (
                        <div style={{ padding: "12px 16px 12px 106px", background: "rgba(0,0,0,0.3)", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                          <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", marginBottom: 4, fontFamily: "'JetBrains Mono', monospace" }}>CATEGORY: {f.category}</div>
                          <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)", marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>MATCHED SNIPPET:</div>
                          <pre style={{ margin: 0, padding: "8px 12px", background: "rgba(255,255,255,0.03)", borderRadius: 4, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: "#f97316", overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                            {f.snippet}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Export */}
            <div style={{ marginTop: 20, display: "flex", gap: 10 }}>
              <button onClick={() => {
                const csv = "Severity,Category,Rule,File,Line,Snippet\n" + findings.map(f =>
                  `"${SEV_LABELS[f.severity]}","${f.category}","${f.rule}","${f.file}","${f.line}","${f.snippet.replace(/"/g, '""')}"`
                ).join("\n");
                const blob = new Blob([csv], { type: "text/csv" });
                const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "sentinel-report.csv"; a.click();
              }} style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", color: "#e2e2e8", padding: "8px 16px", borderRadius: 6, cursor: "pointer", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
                ⬇ Export CSV
              </button>
              <button onClick={() => {
                const report = {
                  scan_date: new Date().toISOString(),
                  risk_score: riskScore,
                  total_findings: findings.length,
                  severity_breakdown: { critical: counts[4], high: counts[3], medium: counts[2], low: counts[1], info: counts[0] },
                  files_scanned: files.map(f => f.name),
                  findings: findings.map(f => ({ ...f, severity: SEV_LABELS[f.severity] }))
                };
                const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
                const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "sentinel-report.json"; a.click();
              }} style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", color: "#e2e2e8", padding: "8px 16px", borderRadius: 6, cursor: "pointer", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
                ⬇ Export JSON
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
