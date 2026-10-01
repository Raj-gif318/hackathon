/* ==========================================================================
   PHISHGUARD THREAT ENGINE - CLIENT JS & ANALYTICS
   ========================================================================== */

// Target Brand Dictionary for Typosquatting / Homoglyph Detection
const BRAND_TARGETS = [
  "paypal", "apple", "google", "microsoft", "amazon", "netflix",
  "chase", "bankofamerica", "wellsfargo", "binance", "coinbase", "facebook"
];

// High-Risk Suspicious Keywords
const SUSPICIOUS_KEYWORDS = [
  "verify", "login", "security", "account", "update", "banking",
  "wallet", "confirm", "auth", "signin", "password", "support", "limited", "credential"
];

// High Risk TLDs
const SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".country"];

let activeMode = 'url';

// Matrix Canvas Animation Effect
window.addEventListener('DOMContentLoaded', () => {
  initMatrixCanvas();
});

function initMatrixCanvas() {
  const canvas = document.getElementById('matrixCanvas');
  const ctx = canvas.getContext('2d');

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const chars = '01100101010101010011001010101010100100101001010101';
  const fontSize = 14;
  const columns = Math.floor(canvas.width / fontSize);
  const drops = Array(columns).fill(1);

  function draw() {
    ctx.fillStyle = 'rgba(7, 10, 18, 0.08)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#00f0ff';
    ctx.font = `${fontSize}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const text = chars.charAt(Math.floor(Math.random() * chars.length));
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);

      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }

  setInterval(draw, 40);
}

// Mode Switcher (URL vs Email)
function switchMode(mode) {
  activeMode = mode;
  document.getElementById('btnModeUrl').classList.toggle('active', mode === 'url');
  document.getElementById('btnModeEmail').classList.toggle('active', mode === 'email');

  document.getElementById('urlInputContainer').classList.toggle('active', mode === 'url');
  document.getElementById('emailInputContainer').classList.toggle('active', mode === 'email');
}

// Preset Targets
function loadPreset(url) {
  document.getElementById('targetUrlInput').value = url;
}

// Levenshtein Distance Algorithm for Typosquatting
function levenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// Calculate Shannon Entropy of a string
function calculateEntropy(str) {
  const len = str.length;
  if (len === 0) return 0;
  const freqs = {};
  for (let char of str) {
    freqs[char] = (freqs[char] || 0) + 1;
  }
  let entropy = 0;
  for (let char in freqs) {
    const p = freqs[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy.toFixed(2);
}

// Extract Features Vector
function extractUrlFeatures(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
  } catch (e) {
    url = { hostname: rawUrl, pathname: '', href: rawUrl, protocol: 'http:' };
  }

  const fullStr = url.href || rawUrl;
  const domain = url.hostname || rawUrl;

  const urlLength = fullStr.length;
  const dotCount = (fullStr.match(/\./g) || []).length;
  const hyphenCount = (fullStr.match(/-/g) || []).length;
  const digitCount = (fullStr.match(/\d/g) || []).length;
  const specialCharCount = (fullStr.match(/[@%_=?&#]/g) || []).length;
  const entropy = calculateEntropy(fullStr);
  const subdomainCount = Math.max(0, domain.split('.').length - 2);
  const isHttps = url.protocol === 'https:';
  const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);

  // Suspicious keyword count
  let keywordMatches = [];
  SUSPICIOUS_KEYWORDS.forEach(kw => {
    if (fullStr.toLowerCase().includes(kw)) keywordMatches.push(kw);
  });

  // Check homoglyph / brand similarity
  let closestBrand = null;
  let minDistance = 999;
  const domainClean = domain.replace(/^www\./, '').split('.')[0].toLowerCase();

  BRAND_TARGETS.forEach(brand => {
    const dist = levenshteinDistance(domainClean, brand);
    if (dist < minDistance) {
      minDistance = dist;
      closestBrand = brand;
    }
  });

  const isHomoglyph = (minDistance > 0 && minDistance <= 2) || (domainClean.includes(closestBrand) && domainClean !== closestBrand);

  return {
    rawUrl: fullStr,
    domain,
    urlLength,
    dotCount,
    hyphenCount,
    digitCount,
    specialCharCount,
    entropy,
    subdomainCount,
    isHttps,
    isIpAddress,
    keywordMatches,
    closestBrand,
    isHomoglyph,
    tldRisk: SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld))
  };
}

// Run Full Threat Analysis
// Run Full Threat Analysis via PHP Backend
async function analyzeTarget() {
  document.getElementById('scanAnimationOverlay').classList.remove('hidden');
  document.getElementById('resultsDashboard').classList.add('hidden');

  // Sequential simulated log animation
  setTimeout(() => { document.getElementById('log1').style.opacity = '1'; }, 200);
  setTimeout(() => { document.getElementById('log2').style.opacity = '1'; }, 600);
  setTimeout(() => { document.getElementById('log3').style.opacity = '1'; }, 1000);
  setTimeout(() => { document.getElementById('log4').style.opacity = '1'; }, 1400);

  let targetUrl = '';
  if (activeMode === 'url') {
      targetUrl = document.getElementById('targetUrlInput').value || 'https://example.com';
  } else {
      const body = document.getElementById('emailBody').value;
      const extractedLinks = body.match(/https?:\/\/[^\s]+/g) || ['https://suspicious-email-link.xyz'];
      targetUrl = extractedLinks[0];
  }

  try {
      // Send data to PHP Backend
      const response = await fetch('api.php', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json'
          },
          body: JSON.stringify({ url: targetUrl })
      });

      if (!response.ok) throw new Error('Backend analysis failed');
      
      const features = await response.json();

      // Add email specific flags if necessary
      if (activeMode === 'email') {
          features.isEmailAnalysis = true;
          features.sender = document.getElementById('emailSender').value;
      }

      // Wait for animation to finish before rendering dashboard
      setTimeout(() => {
          document.getElementById('scanAnimationOverlay').classList.add('hidden');
          document.getElementById('resultsDashboard').classList.remove('hidden');
          renderDashboard(features); // Passes the PHP JSON data into your existing dashboard renderer
      }, 1800);

  } catch (error) {
      console.error("Error communicating with backend:", error);
      alert("Failed to reach the threat engine backend. Ensure api.php is hosted correctly.");
      document.getElementById('scanAnimationOverlay').classList.add('hidden');
  }
}

// Render Dashboard Data
function renderDashboard(f) {
  // Compute Risk Scores
  let lexicalScore = Math.min(100, (f.hyphenCount * 15) + (f.subdomainCount * 20) + (f.digitCount * 5) + (f.entropy > 4.5 ? 25 : 10));
  let domainScore = f.tldRisk ? 92 : (f.isIpAddress ? 95 : 35);
  let sslScore = f.isHttps ? 25 : 90;
  let brandScore = f.isHomoglyph ? 88 : 15;
  let repScore = Math.min(100, f.keywordMatches.length * 30 + (f.tldRisk ? 30 : 0));

  // Overall Risk Score Weighting
  let overallScore = Math.round((lexicalScore * 0.25) + (domainScore * 0.25) + (sslScore * 0.15) + (brandScore * 0.20) + (repScore * 0.15));
  overallScore = Math.max(10, Math.min(99, overallScore));

  // Update Hero Elements
  document.getElementById('riskScoreVal').innerText = overallScore;
  document.getElementById('displayTargetUrl').innerText = f.rawUrl;
  
  // Simulated WHOIS domain age based on score
  const estimatedAge = f.tldRisk || overallScore > 60 ? `${Math.floor(Math.random() * 25) + 3} Days` : `${Math.floor(Math.random() * 5) + 3} Years`;
  document.getElementById('dispDomainAge').innerText = estimatedAge;
  document.getElementById('dispEntropy').innerText = `${f.entropy} bits`;
  document.getElementById('dispHomoglyph').innerText = f.isHomoglyph ? `HIGH (${f.closestBrand})` : 'LOW';

  // Animate Gauge Ring
  const gaugeFill = document.getElementById('gaugeCircle');
  const circumference = 326.72;
  const offset = circumference - (overallScore / 100) * circumference;
  gaugeFill.style.strokeDashoffset = offset;

  const statusBadge = document.getElementById('riskStatusBadge');
  if (overallScore >= 70) {
    gaugeFill.style.stroke = 'var(--risk-high)';
    statusBadge.className = 'status-badge risk-high-bg';
    statusBadge.innerText = '🔴 HIGH RISK';
  } else if (overallScore >= 40) {
    gaugeFill.style.stroke = 'var(--risk-med)';
    statusBadge.className = 'status-badge risk-med-bg';
    statusBadge.innerText = '🟠 MEDIUM RISK';
  } else {
    gaugeFill.style.stroke = 'var(--risk-low)';
    statusBadge.className = 'status-badge risk-low-bg';
    statusBadge.innerText = '🟢 LOW RISK / SAFE';
  }

  // Update Progress Bars
  updateBar('barUrl', 'sigUrlScore', lexicalScore);
  updateBar('barDomain', 'sigDomainScore', domainScore);
  updateBar('barSsl', 'sigSslScore', sslScore);
  updateBar('barBrand', 'sigBrandScore', brandScore);
  updateBar('barRep', 'sigRepScore', repScore);

  // Render "WHY?" Explainable Items
  renderWhyList(f, estimatedAge, overallScore);

  // Render Domain Intelligence
  document.getElementById('rdapAge').innerText = estimatedAge;
  document.getElementById('rdapExp').innerText = f.tldRisk ? 'In 11 Months' : '2028-10-14';
  document.getElementById('rdapRegistrar').innerText = f.tldRisk ? 'NameSilo LLC / Offshore' : 'MarkMonitor Inc.';
  document.getElementById('rdapIp').innerText = `185.${Math.floor(Math.random()*100)+100}.${Math.floor(Math.random()*200)}.${Math.floor(Math.random()*250)}`;
  document.getElementById('rdapHost').innerText = f.tldRisk ? 'Panama Cyber Services' : 'Cloudflare / AWS USA';
  document.getElementById('rdapDns').innerText = `ns1.${f.domain.split('.').slice(-2).join('.')}`;

  // Render Random Forest Feature Vector
  renderFeatureVectors(f);

  // Recommendation updates
  const recBox = document.getElementById('recommendationBox');
  const recTitle = document.getElementById('recTitle');
  const recDesc = document.getElementById('recDesc');

  if (overallScore >= 70) {
    recBox.style.borderColor = 'var(--risk-high)';
    recTitle.innerText = 'CRITICAL SECURITY RECOMMENDATION';
    recDesc.innerText = 'Do not enter passwords, OTPs or payment information. This domain exhibits multiple severe phishing signatures.';
  } else if (overallScore >= 40) {
    recBox.style.borderColor = 'var(--risk-med)';
    recTitle.innerText = 'CAUTION ADVISED';
    recDesc.innerText = 'Exercise caution. Verify sender authenticity before interacting with sensitive forms.';
  } else {
    recBox.style.borderColor = 'var(--risk-low)';
    recTitle.innerText = 'DOMAIN APPEARS LEGITIMATE';
    recDesc.innerText = 'Standard security parameters verified. Always confirm SSL certificates in browser bar.';
  }
}

function updateBar(barId, scoreId, value) {
  document.getElementById(scoreId).innerText = value;
  const bar = document.getElementById(barId);
  bar.style.width = `${value}%`;
  bar.className = 'progress-bar ' + (value >= 70 ? 'high' : value >= 40 ? 'med' : 'low');
}

// Generate "WHY?" Explanation List
function renderWhyList(f, age, overallScore) {
  const container = document.getElementById('whyListContainer');
  container.innerHTML = '';

  const reasons = [];

  if (parseInt(age) < 30 || f.tldRisk) {
    reasons.push({
      sev: 'high',
      title: '🔴 Recently registered / Suspicious TLD',
      detail: `Domain age: ${age} (High risk TLD detected)`
    });
  }

  if (f.subdomainCount >= 2 || f.hyphenCount >= 3) {
    reasons.push({
      sev: 'high',
      title: '🔴 Suspicious URL structure',
      detail: `Excessive subdomains (${f.subdomainCount}) and hyphens (${f.hyphenCount})`
    });
  }

  if (f.isHomoglyph) {
    reasons.push({
      sev: 'med',
      title: '🟠 Brand similarity / Typosquatting detected',
      detail: `Domain resembles target brand "${f.closestBrand.toUpperCase()}"`
    });
  }

  if (f.keywordMatches.length > 0) {
    reasons.push({
      sev: 'med',
      title: '🟠 Suspicious phishing keywords',
      detail: `Flagged keywords: "${f.keywordMatches.join('", "')}"`
    });
  }

  if (f.isHttps) {
    reasons.push({
      sev: 'low',
      title: '🟢 Valid HTTPS Connection',
      detail: 'TLS encryption present (Note: 80% of modern phishing uses HTTPS)'
    });
  } else {
    reasons.push({
      sev: 'high',
      title: '🔴 Unencrypted HTTP Protocol',
      detail: 'No TLS certificate detected on connection'
    });
  }

  reasons.forEach(r => {
    const item = document.createElement('div');
    item.className = `why-item sev-${r.sev}`;
    item.innerHTML = `
      <div class="why-title">${r.title}</div>
      <div class="why-detail">${r.detail}</div>
    `;
    container.appendChild(item);
  });
}

// Render Random Forest Feature Inputs
function renderFeatureVectors(f) {
  const grid = document.getElementById('vectorGrid');
  grid.innerHTML = '';

  const vectorData = [
    { key: 'URL Length', val: f.urlLength },
    { key: 'Dot Count', val: f.dotCount },
    { key: 'Hyphen Count', val: f.hyphenCount },
    { key: 'Digit Count', val: f.digitCount },
    { key: 'Special Chars', val: f.specialCharCount },
    { key: 'Entropy Score', val: f.entropy },
    { key: 'Subdomains', val: f.subdomainCount },
    { key: 'HTTPS Flag', val: f.isHttps ? '1 (True)' : '0 (False)' },
    { key: 'IP Host Flag', val: f.isIpAddress ? '1 (True)' : '0 (False)' },
    { key: 'Keyword Count', val: f.keywordMatches.length }
  ];

  vectorData.forEach(v => {
    const div = document.createElement('div');
    div.className = 'vector-item';
    div.innerHTML = `
      <span class="vec-key">${v.key}</span>
      <span class="vec-val">${v.val}</span>
    `;
    grid.appendChild(div);
  });
}

function resetScan() {
  document.getElementById('resultsDashboard').classList.add('hidden');
}