const resultsDiv = document.getElementById("results");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runTest(name, fn) {
  try {
    fn();
    resultsDiv.innerHTML += `
      <div class="test-result pass">
        <div class="test-name">✅ ${name}</div>
      </div>
    `;
  } catch (err) {
    resultsDiv.innerHTML += `
      <div class="test-result fail">
        <div class="test-name">❌ ${name}</div>
        <div class="test-msg">${err.message}</div>
      </div>
    `;
    console.error(`Test Failed: ${name}`, err);
  }
}

// -------------------------
// Tests for URL Analyzer
// -------------------------
runTest("URL Analyzer: Safe domain should score 0", () => {
  const result = window.UrlAnalyzer.analyzeUrl("https://www.google.com/search");
  assert(result.isSuspicious === false, "Should not be suspicious");
  assert(result.score === 0, "Score should be 0");
});

runTest("URL Analyzer: Trusted domains correctly identified", () => {
  assert(window.UrlAnalyzer.isTrustedDomain("github.com") === true, "github is trusted");
  assert(window.UrlAnalyzer.isTrustedDomain("accounts.google.com") === true, "accounts.google is trusted");
  assert(window.UrlAnalyzer.isTrustedDomain("malicious-site.tk") === false, ".tk is not trusted");
});

runTest("URL Analyzer: Typosquatting detection", () => {
  const result = window.UrlAnalyzer.analyzeUrl("http://paypa1-secure-login.com/verify");
  assert(result.isSuspicious === true, "Should be flagged as suspicious");
  assert(result.score > 0, "Score should be > 0");
  assert(result.reason.includes("keyword"), "Should detect suspicious keyword");
});

runTest("URL Analyzer: High entropy domain", () => {
  const result = window.UrlAnalyzer.analyzeUrl("http://a1b2c3d4e5f6g7h8i9j0klmnopqrstu.com");
  assert(result.score >= 20, "Should have entropy score");
  assert(result.reason.includes("entropy"), "Should mention entropy in reason");
});

runTest("URL Analyzer: Punycode/IDN homoglyph", () => {
  const result = window.UrlAnalyzer.analyzeUrl("https://xn--g00gle-9db.com");
  assert(result.score >= 30, "Should penalize punycode");
  assert(result.reason.includes("Punycode"), "Should mention punycode");
});
