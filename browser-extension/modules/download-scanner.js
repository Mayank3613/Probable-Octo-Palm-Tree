// OctoPlamTree Download Scanner v2.0 — ES6 module for background.js

// ── Constants ────────────────────────────────────────────────────────────────
const DANGEROUS_EXTS = new Set(["exe","msi","bat","cmd","scr","vbs","js","jse","wsf","wsh","pif","lnk","reg","hta","cpl","jar","ps1","vbe","com","inf","dll","sys","drv","ocx","ade","adp","app","bas"]);
const SAFE_EXTS      = new Set(["pdf","doc","docx","xls","xlsx","ppt","pptx","png","jpg","jpeg","gif","txt","zip","rar","7z","mp4","mp3","csv"]);
const BAD_TLDS       = new Set(["tk","ml","ga","cf","gq","xyz","top","buzz","club","icu"]);
const BAD_MIME_EXTS  = {
  // maps declared MIME type → extensions that should NEVER carry it
  "application/octet-stream": ["pdf","png","jpg","jpeg","gif","mp4","mp3","txt"],
  "text/html":                ["exe","msi","bat","scr","vbs","js"],
  "image/jpeg":               ["exe","msi","bat","vbs","js","zip"],
  "image/png":                ["exe","msi","bat","vbs","js","zip"],
  "application/pdf":          ["exe","msi","bat","vbs","js"],
};
// MIME types that should only appear for genuine executables
const EXEC_MIMES = new Set(["application/x-msdownload","application/x-executable","application/x-mach-binary","application/x-elf","application/x-dosexec"]);

// RTL / homograph Unicode ranges that are used to visually spoof filenames
const RTL_CHARS   = /[\u200F\u200E\u202A-\u202E\u2066-\u2069\u061C]/;
const CONFUSE_RE  = /[\u0400-\u04FF\u0370-\u03FF\u0430-\u044F]/; // Cyrillic / Greek mixed with Latin

// VirusTotal public API v3 file hash lookup (API key injected at runtime via VT_API_KEY)
const VT_ENDPOINT = "https://www.virustotal.com/api/v3/files/";

// Archive MIME types we can request inspection for
const ARCHIVE_MIMES = new Set(["application/zip","application/x-rar-compressed","application/x-7z-compressed","application/gzip","application/x-tar","application/x-bzip2","application/java-archive"]);
// Dangerous extensions inside archives
const ARCHIVE_DANGEROUS_RE = /\.(exe|msi|bat|cmd|scr|vbs|jse|wsf|pif|lnk|hta|ps1|dll|com)$/i;

// Download reputation: ring-buffer of the last 50 downloads per host
const reputationLog = [];
const REP_WINDOW    = 10 * 60 * 1000; // 10 minutes
const REP_THRESHOLD = 5;              // >5 flagged downloads from same host = high-risk

// ── Helpers ──────────────────────────────────────────────────────────────────
const tld      = h => h.split(".").pop().toLowerCase();
const basename = p => p.split(/[/\\]/).pop();
const ext      = f => (f.split(".").pop() || "").toLowerCase();
const exts     = f => f.split(".").slice(1).map(e => e.toLowerCase()); // all extensions

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function score(results, pts, reason, severity = "medium") {
  results.score = Math.min(100, results.score + pts);
  results.reasons.push({ reason, severity });
  if (results.score >= 50) results.isSuspicious = true;
}

// ── 1. MIME Validation ───────────────────────────────────────────────────────
// Checks declared MIME type against file extension for spoofing.
function validateMime(mimeType, filename, results) {
  if (!mimeType) return;
  const mime = mimeType.split(";")[0].trim().toLowerCase();
  const fileExt = ext(filename);

  // Executable MIME served with a non-executable extension → masquerade
  if (EXEC_MIMES.has(mime) && !DANGEROUS_EXTS.has(fileExt))
    score(results, 70, `MIME "${mime}" declared for non-executable extension ".${fileExt}" — content masquerade`, "high");

  // Non-executable MIME served with a dangerous extension
  const mismatchExts = BAD_MIME_EXTS[mime];
  if (mismatchExts && mismatchExts.includes(fileExt))
    score(results, 60, `MIME "${mime}" mismatches extension ".${fileExt}" — likely spoofed content type`, "high");

  // application/octet-stream on a "safe" extension is a common dropper trick
  if (mime === "application/octet-stream" && DANGEROUS_EXTS.has(fileExt))
    score(results, 40, `Generic MIME "application/octet-stream" for executable ".${fileExt}"`, "medium");

  // Archive MIME but extension is an executable
  if (ARCHIVE_MIMES.has(mime) && DANGEROUS_EXTS.has(fileExt))
    score(results, 55, `Archive MIME "${mime}" but file is ".${fileExt}" — zipped dropper pattern`, "high");
}

// ── 2. Unicode / RTL Detection ────────────────────────────────────────────────
// Detects RTL override characters and homograph spoofing in filenames.
function detectUnicode(filename, results) {
  if (RTL_CHARS.test(filename)) {
    // Find the "real" extension hidden by RTL override — e.g. "documentU+202Egpj.exe" displays as "document.exeU+202Ejpg"
    const reversed = [...filename].reverse().join("");
    const visibleExt = ext(reversed);
    score(results, 85,
      `RTL Unicode override detected in filename "${filename}"${visibleExt ? ` — visually appears as ".${visibleExt}"` : ""}`,
      "critical"
    );
  }
  if (CONFUSE_RE.test(filename) && /[a-z]/i.test(filename))
    score(results, 50, `Homograph characters (Cyrillic/Greek mixed with Latin) in filename "${filename}" — visual spoofing`, "high");

  // Zero-width chars as name padding
  if (/[\u200B\u200C\u200D\uFEFF]/.test(filename))
    score(results, 40, `Zero-width Unicode characters in filename — may hide true extension`, "medium");
}

// ── 3. VirusTotal Hash Lookup ─────────────────────────────────────────────────
// Queries VT API v3 with the file's SHA-256 hash (provided by Chrome's download API).
// Returns a structured result; caller decides how to emit alerts.
async function vtHashLookup(sha256, apiKey) {
  if (!sha256 || !apiKey) return null;
  try {
    const res = await fetch(`${VT_ENDPOINT}${sha256}`, {
      headers: { "x-apikey": apiKey },
    });
    if (res.status === 404) return { known: false };
    if (!res.ok) return null;
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const total    = Object.values(stats).reduce((s, n) => s + n, 0);
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    return {
      known:      true,
      malicious,
      suspicious,
      total,
      ratio:      total ? ((malicious + suspicious) / total) : 0,
      permalink:  data?.data?.links?.self || null,
      name:       data?.data?.attributes?.meaningful_name || null,
    };
  } catch { return null; }
}

function applyVTResult(vtResult, results) {
  if (!vtResult) return;
  if (!vtResult.known) {
    score(results, 20, "File hash unknown to VirusTotal — never seen before (zero-day risk)", "medium");
    return;
  }
  const { malicious, suspicious, total, ratio, permalink } = vtResult;
  if (malicious > 0) {
    const sev = malicious >= 5 ? "critical" : malicious >= 2 ? "high" : "medium";
    score(results, Math.min(100, malicious * 15),
      `VirusTotal: ${malicious}/${total} engines flagged as malicious${permalink ? ` — ${permalink}` : ""}`, sev);
  } else if (suspicious > 0) {
    score(results, suspicious * 8, `VirusTotal: ${suspicious}/${total} engines flagged as suspicious`, "medium");
  } else if (total > 0) {
    // Clean signal — subtract score (up to -20) as trust boost
    results.score = Math.max(0, results.score - 20);
    results.reasons.push({ reason: `VirusTotal: 0/${total} detections — file is clean`, severity: "info" });
  }
}

// ── 4. Archive Inspection ─────────────────────────────────────────────────────
// Inspects the download URL or filename for archive-specific red flags.
// Full byte-level inspection requires a native host; this covers static signals.
function inspectArchive(filename, mimeType, results) {
  const mime = (mimeType || "").split(";")[0].trim().toLowerCase();
  if (!ARCHIVE_MIMES.has(mime) && !["zip","rar","7z","gz","tar","bz2","jar"].includes(ext(filename))) return;

  // Password-protected hint in filename (common in malware drops)
  if (/pass(word)?|passwd|pwd/i.test(filename))
    score(results, 55, `Archive filename suggests password protection ("${basename(filename)}") — common malware delivery pattern`, "high");

  // Nested archive naming (zip-in-zip, rar-in-zip etc.)
  const allExts = exts(filename);
  const archiveCount = allExts.filter(e => ["zip","rar","7z","gz","tar","bz2","jar"].includes(e)).length;
  if (archiveCount >= 2)
    score(results, 60, `Nested archive pattern in filename: "${basename(filename)}" — double-compression used to evade scanners`, "high");

  // .jar archives from untrusted domains deserve extra scrutiny
  if (ext(filename) === "jar")
    score(results, 30, `Java Archive (.jar) download — arbitrary code execution if opened`, "medium");
}

// Archive manifest inspection (called with list of filenames inside the archive,
// e.g. from a native-host message or background ZIP parser)
export function inspectArchiveManifest(filelist = [], downloadResults) {
  const dangerous = filelist.filter(f => ARCHIVE_DANGEROUS_RE.test(f));
  if (!dangerous.length) return;
  const sev = dangerous.length >= 3 ? "critical" : "high";
  score(downloadResults, dangerous.length * 20,
    `Archive contains ${dangerous.length} dangerous file(s): [${dangerous.slice(0, 5).join(", ")}]`, sev);
}

// ── 5. Download Reputation Correlation ───────────────────────────────────────
// Tracks flagged downloads per host in a time-windowed ring buffer.
// Escalates if the same host delivers multiple suspicious files.
function updateReputation(host, isFlagged, results) {
  const now = Date.now();
  // Prune old entries
  while (reputationLog.length && reputationLog[0].ts < now - REP_WINDOW) reputationLog.shift();

  if (isFlagged) reputationLog.push({ ts: now, host });

  const hostCount = reputationLog.filter(e => e.host === host).length;
  if (hostCount >= REP_THRESHOLD)
    score(results, 40, `Reputation: ${hostCount} flagged downloads from "${host}" in the last 10 min — high-risk host`, "high");
  else if (hostCount >= 2)
    score(results, 15, `Reputation: ${hostCount} flagged downloads from "${host}" — host under observation`, "medium");
}

export function getReputationLog() { return [...reputationLog]; }

// ── Core scanner ──────────────────────────────────────────────────────────────
export async function scanDownload(downloadItem, options = {}) {
  // options: { vtApiKey, archiveManifest }
  const filename = downloadItem.filename || "";
  const url      = downloadItem.url      || "";
  const mime     = downloadItem.mime     || downloadItem.mimeType || "";
  const sha256   = downloadItem.sha256   || downloadItem.hash     || "";

  const results = {
    isSuspicious: false,
    score: 0,
    reasons: [],
    // convenience getter for legacy callers
    get reason() { return this.reasons.map(r => r.reason).join(" | "); },
  };

  if (!filename) return results;

  const clean   = basename(filename);
  const allExts = exts(clean);
  const primExt = allExts.at(-1) || "";
  const host    = hostOf(url);

  // ── Static heuristics ────────────────────────────────────────────────────
  // Heuristic 1: Double-extension attack
  if (allExts.length >= 2) {
    const secondExt = allExts.at(-2);
    if (SAFE_EXTS.has(secondExt) && DANGEROUS_EXTS.has(primExt))
      score(results, 90, `Double-extension attack: ".${secondExt}.${primExt}"`, "critical");
  }

  // Heuristic 2: Dangerous primary extension
  if (DANGEROUS_EXTS.has(primExt))
    score(results, 50, `Dangerous executable extension: ".${primExt}"`, "high");

  // Heuristic 3: Suspicious TLD source
  if (host && BAD_TLDS.has(tld(host)))
    score(results, 35, `Downloaded from suspicious TLD host: ${host}`, "medium");

  // Heuristic 4: Excessive dots (evasion padding)
  if (allExts.length >= 4)
    score(results, 25, `Filename has ${allExts.length} extensions — evasion padding: "${clean}"`, "medium");

  // ── New feature checks ────────────────────────────────────────────────────
  validateMime(mime, clean, results);           // 1. MIME validation
  detectUnicode(filename, results);             // 2. RTL / homograph detection
  inspectArchive(clean, mime, results);         // 4. Archive static inspection

  // Archive manifest (if caller provided a file list from inside the archive)
  if (options.archiveManifest?.length)
    inspectArchiveManifest(options.archiveManifest, results);

  // 3. VirusTotal hash lookup (async)
  if (sha256 && options.vtApiKey) {
    const vtResult = await vtHashLookup(sha256, options.vtApiKey);
    applyVTResult(vtResult, results);
  }

  // 5. Reputation correlation (uses whether THIS download is already flagged)
  if (host) updateReputation(host, results.isSuspicious, results);

  // Final gate
  results.isSuspicious = results.score >= 50;
  return results;
}