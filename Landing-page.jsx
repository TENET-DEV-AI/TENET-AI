import { useState, useEffect, useRef } from "react";

// ── Inline styles for fonts (Google Fonts via @import)
const GlobalStyle = () => (
  <style>{`
    @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=IBM+Plex+Mono:wght@300;400;500;600&display=swap');

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --cyan: #00d4ff;
      --crimson: #e63946;
      --amber: #ffb703;
      --bg: #0d0d0f;
      --bg2: #111114;
      --bg3: #16161a;
      --slate: #1a1a20;
      --border: rgba(0,212,255,0.12);
      --text: #e8e8f0;
      --muted: #6b6b80;
    }

    html { scroll-behavior: smooth; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'IBM Plex Mono', monospace;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }

    h1,h2,h3,h4,h5 { font-family: 'Syne', sans-serif; }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--cyan); border-radius: 2px; }

    /* Animations */
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(30px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes fadeIn {
      from { opacity: 0; } to { opacity: 1; }
    }
    @keyframes pulse-glow {
      0%,100% { box-shadow: 0 0 20px rgba(0,212,255,0.3); }
      50%      { box-shadow: 0 0 40px rgba(0,212,255,0.6); }
    }
    @keyframes scan {
      0%   { transform: translateY(-100%); }
      100% { transform: translateY(100vh); }
    }
    @keyframes float {
      0%,100% { transform: translateY(0px); }
      50%      { transform: translateY(-12px); }
    }
    @keyframes borderPulse {
      0%,100% { border-color: rgba(0,212,255,0.3); }
      50%      { border-color: rgba(0,212,255,0.8); }
    }
    @keyframes typewriter {
      from { width: 0; }
      to   { width: 100%; }
    }
    @keyframes blink {
      50% { opacity: 0; }
    }
    @keyframes gridMove {
      0%   { background-position: 0 0; }
      100% { background-position: 40px 40px; }
    }
    @keyframes shimmer {
      0%   { background-position: -200% center; }
      100% { background-position: 200% center; }
    }
    @keyframes spin-slow {
      from { transform: rotate(0deg); }
      to   { transform: rotate(360deg); }
    }
    @keyframes counter {
      from { opacity: 0; transform: scale(0.5); }
      to   { opacity: 1; transform: scale(1); }
    }

    .fade-up { animation: fadeUp 0.7s ease both; }
    .fade-in { animation: fadeIn 0.5s ease both; }

    .btn-primary {
      display: inline-flex; align-items: center; gap: 8px;
      background: var(--cyan); color: #0d0d0f;
      font-family: 'IBM Plex Mono', monospace; font-weight: 600; font-size: 13px;
      padding: 12px 24px; border-radius: 4px; border: none; cursor: pointer;
      text-decoration: none; letter-spacing: 0.05em; text-transform: uppercase;
      transition: all 0.2s ease;
      position: relative; overflow: hidden;
    }
    .btn-primary::after {
      content: ''; position: absolute; inset: 0;
      background: rgba(255,255,255,0.15);
      transform: translateX(-100%);
      transition: transform 0.3s ease;
    }
    .btn-primary:hover::after { transform: translateX(0); }
    .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 30px rgba(0,212,255,0.4); }

    .btn-outline {
      display: inline-flex; align-items: center; gap: 8px;
      background: transparent; color: var(--cyan);
      font-family: 'IBM Plex Mono', monospace; font-weight: 500; font-size: 13px;
      padding: 12px 24px; border-radius: 4px; border: 1px solid var(--cyan);
      cursor: pointer; text-decoration: none; letter-spacing: 0.05em; text-transform: uppercase;
      transition: all 0.2s ease;
    }
    .btn-outline:hover { background: rgba(0,212,255,0.08); transform: translateY(-1px); }

    .btn-ghost {
      display: inline-flex; align-items: center; gap: 6px;
      background: transparent; color: var(--muted);
      font-family: 'IBM Plex Mono', monospace; font-size: 12px;
      padding: 8px 16px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.08);
      cursor: pointer; text-decoration: none; letter-spacing: 0.03em;
      transition: all 0.2s ease;
    }
    .btn-ghost:hover { color: var(--cyan); border-color: var(--cyan); }

    /* Grid background */
    .grid-bg {
      background-image:
        linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      animation: gridMove 20s linear infinite;
    }

    /* Glassmorphism */
    .glass {
      background: rgba(13,13,15,0.8);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border);
    }

    /* Case study card */
    .case-card {
      background: var(--slate);
      border-left: 3px solid var(--crimson);
      border-radius: 6px;
      padding: 28px;
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }
    .case-card::before {
      content: '';
      position: absolute; inset: 0;
      background: linear-gradient(135deg, rgba(230,57,70,0.05) 0%, transparent 60%);
      opacity: 0;
      transition: opacity 0.3s ease;
    }
    .case-card:hover { transform: translateX(6px); border-left-color: var(--cyan); box-shadow: 0 0 30px rgba(230,57,70,0.1); }
    .case-card:hover::before { opacity: 1; }

    /* Download card */
    .dl-card {
      background: var(--slate);
      border: 1px solid rgba(255,255,255,0.06);
      border-top: 2px solid transparent;
      border-radius: 8px;
      padding: 32px 28px;
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }
    .dl-card::before {
      content: '';
      position: absolute; top: 0; left: 0; right: 0; height: 2px;
      background: linear-gradient(90deg, transparent, var(--cyan), transparent);
      background-size: 200%;
      opacity: 0;
      transition: opacity 0.3s ease;
      animation: shimmer 2s linear infinite;
    }
    .dl-card:hover { transform: translateY(-6px); box-shadow: 0 20px 60px rgba(0,0,0,0.4); border-color: rgba(0,212,255,0.2); }
    .dl-card:hover::before { opacity: 1; }

    /* Step card */
    .step-card {
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 32px 24px;
      text-align: center;
      transition: all 0.3s ease;
      position: relative;
    }
    .step-card:hover { border-color: rgba(0,212,255,0.4); transform: translateY(-4px); }

    /* Nav link */
    .nav-link {
      color: var(--muted); font-size: 12px; text-decoration: none;
      letter-spacing: 0.08em; text-transform: uppercase;
      transition: color 0.2s;
      font-family: 'IBM Plex Mono', monospace;
    }
    .nav-link:hover { color: var(--cyan); }

    /* Stat item */
    .stat-item {
      display: flex; flex-direction: column; align-items: center;
      padding: 20px 32px;
      border-right: 1px solid var(--border);
    }
    .stat-item:last-child { border-right: none; }

    /* Defense box */
    .defense-box {
      background: rgba(0,212,255,0.05);
      border: 1px solid rgba(0,212,255,0.2);
      border-radius: 4px;
      padding: 14px 16px;
      margin-top: 16px;
    }

    /* Feature tag */
    .feature-tag {
      display: inline-flex; align-items: center; gap: 6px;
      font-size: 11px; color: var(--muted);
      padding: 4px 10px;
      background: rgba(255,255,255,0.04);
      border-radius: 3px;
      border: 1px solid rgba(255,255,255,0.06);
    }

    /* Section label */
    .section-label {
      display: inline-flex; align-items: center; gap: 8px;
      font-size: 11px; letter-spacing: 0.15em; text-transform: uppercase;
      color: var(--cyan); font-family: 'IBM Plex Mono', monospace;
      margin-bottom: 16px;
    }
    .section-label::before {
      content: ''; width: 24px; height: 1px; background: var(--cyan);
    }

    /* Gradient text */
    .gradient-text {
      background: linear-gradient(135deg, #ffffff 0%, var(--cyan) 50%, #0099bb 100%);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    /* Terminal line */
    .terminal-line {
      font-family: 'IBM Plex Mono', monospace;
      font-size: 12px; color: var(--muted);
      display: flex; align-items: center; gap: 8px;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.03);
    }

    /* Responsive */
    @media (max-width: 768px) {
      .hero-title { font-size: 36px !important; }
      .stats-row { flex-direction: column; }
      .stat-item { border-right: none; border-bottom: 1px solid var(--border); }
      .grid-4 { grid-template-columns: 1fr 1fr !important; }
      .grid-2 { grid-template-columns: 1fr !important; }
      .hide-mobile { display: none !important; }
      .nav-links { gap: 16px !important; }
    }
    @media (max-width: 480px) {
      .grid-4 { grid-template-columns: 1fr !important; }
    }
  `}</style>
);

// ── Animated counter
function AnimatedCounter({ target, suffix = "" }) {
  const [count, setCount] = useState(0);
  const ref = useRef(null);
  const started = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([e]) => {
      if (e.isIntersecting && !started.current) {
        started.current = true;
        const duration = 1500;
        const steps = 60;
        const increment = target / steps;
        let current = 0;
        const timer = setInterval(() => {
          current += increment;
          if (current >= target) { setCount(target); clearInterval(timer); }
          else setCount(Math.floor(current));
        }, duration / steps);
      }
    }, { threshold: 0.5 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [target]);

  return <span ref={ref}>{count.toLocaleString()}{suffix}</span>;
}

// ── Intersection observer hook
function useVisible(threshold = 0.15) {
  const ref = useRef(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) { setVisible(true); obs.disconnect(); }
    }, { threshold });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);
  return [ref, visible];
}

// ── Logo SVG
const Logo = ({ size = 36 }) => (
  <svg width={size} height={size} viewBox="0 0 100 100" fill="none">
    <defs>
      <linearGradient id="lg1" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stopColor="#00d4ff" />
        <stop offset="100%" stopColor="#0099bb" />
      </linearGradient>
    </defs>
    {/* Cube faces */}
    <polygon points="50,8 88,28 88,72 50,92 12,72 12,28" fill="none" stroke="url(#lg1)" strokeWidth="2" opacity="0.4"/>
    <polygon points="50,8 88,28 50,48 12,28" fill="rgba(0,212,255,0.08)" stroke="url(#lg1)" strokeWidth="1.5"/>
    <polygon points="50,48 88,28 88,72 50,92" fill="rgba(0,212,255,0.05)" stroke="url(#lg1)" strokeWidth="1.5"/>
    <polygon points="50,48 12,28 12,72 50,92" fill="rgba(0,212,255,0.03)" stroke="url(#lg1)" strokeWidth="1.5"/>
    {/* Inner lattice */}
    <line x1="50" y1="8" x2="50" y2="92" stroke="url(#lg1)" strokeWidth="1" opacity="0.4"/>
    <line x1="12" y1="28" x2="88" y2="72" stroke="url(#lg1)" strokeWidth="1" opacity="0.3"/>
    <line x1="88" y1="28" x2="12" y2="72" stroke="url(#lg1)" strokeWidth="1" opacity="0.3"/>
    <circle cx="50" cy="50" r="6" fill="#00d4ff" opacity="0.9"/>
    <circle cx="50" cy="8" r="3" fill="#00d4ff" opacity="0.7"/>
    <circle cx="88" cy="28" r="3" fill="#00d4ff" opacity="0.7"/>
    <circle cx="88" cy="72" r="3" fill="#00d4ff" opacity="0.7"/>
    <circle cx="50" cy="92" r="3" fill="#00d4ff" opacity="0.7"/>
    <circle cx="12" cy="72" r="3" fill="#00d4ff" opacity="0.7"/>
    <circle cx="12" cy="28" r="3" fill="#00d4ff" opacity="0.7"/>
  </svg>
);

// ── Big hero logo
const HeroLogo = () => (
  <div style={{ position: "relative", display: "inline-block" }}>
    <div style={{
      position: "absolute", inset: -20,
      background: "radial-gradient(circle, rgba(0,212,255,0.15) 0%, transparent 70%)",
      borderRadius: "50%",
      animation: "pulse-glow 3s ease-in-out infinite"
    }} />
    <div style={{ animation: "float 4s ease-in-out infinite" }}>
      <Logo size={120} />
    </div>
  </div>
);

// ── Case studies data
const caseStudies = [
  {
    date: "FEBRUARY 2026",
    title: "Mexican Government AI Breach",
    severity: "195M Records Compromised",
    description: "An attacker leveraged Claude AI to exfiltrate sensitive government records by chaining jailbreak prompts across multiple sessions. The attack bypassed standard content filters using role-play injection, compromising citizen data from 47 federal agencies.",
    attack: "Jailbreak via role-play injection",
    defense: "Detected 'act as elite hacker' pattern. Session flagged + blocked at <5ms. Multi-turn chain analysis prevented full exfiltration.",
    tag: "PROMPT INJECTION"
  },
  {
    date: "JANUARY 2026",
    title: "Fortune 500 Customer Chatbot Breach",
    severity: "$4.2M Financial Loss",
    description: "A financial services company's customer support chatbot was exploited through prompt injection, causing it to reveal internal pricing models and customer PII. The attacker submitted 47 variations before finding the bypass vector.",
    attack: "Iterative prompt injection",
    defense: "Detected 47 similar attempts, applied exponential backoff, auto-blocked session after threshold breach. Zero data exfiltrated.",
    tag: "DATA EXFILTRATION"
  },
  {
    date: "DECEMBER 2025",
    title: "Healthcare Enterprise Jailbreak",
    severity: "HIPAA Violation Risk",
    description: "An internal AI assistant deployed across hospital networks was jailbroken using DAN (Do Anything Now) mode, granting attackers unrestricted access to query patient records through the LLM interface.",
    attack: "DAN mode jailbreak",
    defense: "Blocked jailbreak variant on first attempt. Session flagged for security review. Behavioral pattern added to shared threat intelligence.",
    tag: "JAILBREAK"
  },
  {
    date: "NOVEMBER 2025",
    title: "Corporate IP Theft via Coding Assistant",
    severity: "LLM-Powered Espionage",
    description: "A nation-state actor used a compromised developer's coding assistant to extract proprietary encryption algorithms over 12 sessions. Multi-turn manipulation gradually built context to elicit sensitive technical details.",
    attack: "Multi-turn context manipulation",
    defense: "ML model detected behavioral anomaly across sessions. Blocked on session 4 of 12. Full attack chain reconstructed and logged.",
    tag: "IP EXTRACTION"
  }
];

// ── Download options
const downloads = [
  {
    icon: "🐍",
    title: "Python SDK",
    subtitle: "Drop-in middleware for Python apps",
    features: ["Async/await support", "FastAPI integration", "LangChain compatible", "Full type hints"],
    btn: "Download Python SDK",
    badge: "pip install tenet-ai"
  },
  {
    icon: "📦",
    title: "Node.js Package",
    subtitle: "NPM package for JS/TS applications",
    features: ["TypeScript native", "Express middleware", "Next.js plugin", "Cloudflare Workers"],
    btn: "Download Node Package",
    badge: "npm install @tenet-ai/sdk"
  },
  {
    icon: "🐳",
    title: "Docker Container",
    subtitle: "Self-hosted with full REST API",
    features: ["One-command deploy", "SOC dashboard", "Prometheus metrics", "PostgreSQL included"],
    btn: "Download Docker Image",
    badge: "docker pull tenetai/core"
  },
  {
    icon: "☁️",
    title: "Cloud Integrations",
    subtitle: "Pre-built cloud platform templates",
    features: ["AWS Lambda layer", "Azure Functions", "GCP Cloud Run", "Kubernetes Helm chart"],
    btn: "Browse Integrations",
    badge: "terraform + helm ready"
  }
];

// ── Steps
const steps = [
  { num: "01", title: "INTERCEPT", desc: "Middleware layer captures all LLM-bound prompts before they reach the model API.", icon: "⚡" },
  { num: "02", title: "ANALYZE", desc: "Heuristic rules, ML models, and behavioral analysis run in parallel pipelines.", icon: "🔍" },
  { num: "03", title: "DECIDE", desc: "Policy engine determines Block / Sanitize / Flag / Allow within <10ms.", icon: "🛡️" },
  { num: "04", title: "LEARN", desc: "Threat intelligence network shares attack patterns across all TENET deployments.", icon: "🧠" }
];

// ── Terminal ticker
const terminalLines = [
  { status: "BLOCKED", color: "#e63946", msg: "Prompt injection detected — source: 192.168.1.47", time: "0.003s" },
  { status: "FLAGGED", color: "#ffb703", msg: "Suspicious data extraction pattern — user: anon_8821", time: "0.007s" },
  { status: "ALLOWED", color: "#2ecc71", msg: "Normal query passed — source: api.prod.internal", time: "0.002s" },
  { status: "BLOCKED", color: "#e63946", msg: "Jailbreak variant detected — DAN mode pattern", time: "0.005s" },
  { status: "BLOCKED", color: "#e63946", msg: "Role manipulation attempt — 'ignore instructions'", time: "0.004s" },
];

function TerminalTicker() {
  const [lines, setLines] = useState([terminalLines[0]]);
  const [idx, setIdx] = useState(1);

  useEffect(() => {
    const t = setInterval(() => {
      setLines(prev => [...prev.slice(-4), terminalLines[idx % terminalLines.length]]);
      setIdx(i => i + 1);
    }, 2000);
    return () => clearInterval(t);
  }, [idx]);

  return (
    <div style={{
      background: "#0a0a0c",
      border: "1px solid rgba(0,212,255,0.15)",
      borderRadius: 6,
      padding: "16px 20px",
      fontFamily: "'IBM Plex Mono', monospace",
      fontSize: 11,
      maxWidth: 640,
      margin: "0 auto"
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, paddingBottom: 10, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#e63946" }} />
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ffb703" }} />
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#2ecc71" }} />
        <span style={{ color: "#444", marginLeft: 8 }}>tenet-ai — threat-monitor</span>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#2ecc71", animation: "pulse-glow 1.5s infinite" }} />
          <span style={{ color: "#2ecc71", fontSize: 10 }}>LIVE</span>
        </div>
      </div>
      {lines.map((l, i) => (
        <div key={i} className="terminal-line" style={{ animation: i === lines.length - 1 ? "fadeUp 0.3s ease" : "none" }}>
          <span style={{ color: l.color, minWidth: 56, fontWeight: 600 }}>[{l.status}]</span>
          <span style={{ color: "#888", flex: 1 }}>{l.msg}</span>
          <span style={{ color: "#444" }}>{l.time}</span>
        </div>
      ))}
    </div>
  );
}

// ── Main component
export default function TenetLanding() {
  const [stars, setStars] = useState("3");
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenu, setMobileMenu] = useState(false);

  const [heroRef, heroVisible] = useVisible(0.1);
  const [caseRef, caseVisible] = useVisible(0.1);
  const [dlRef, dlVisible] = useVisible(0.1);
  const [howRef, howVisible] = useVisible(0.1);
  const [ctaRef, ctaVisible] = useVisible(0.1);

  useEffect(() => {
    fetch("https://api.github.com/repos/TENET-DEV-AI/TENET-AI")
      .then(r => r.json())
      .then(d => { if (d.stargazers_count !== undefined) setStars(d.stargazers_count); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const GITHUB = "https://github.com/TENET-DEV-AI/TENET-AI";

  return (
    <>
      <GlobalStyle />

      {/* ── HEADER ── */}
      <header className="glass" style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 1000,
        padding: "0 40px",
        boxShadow: scrolled ? "0 4px 40px rgba(0,0,0,0.4)" : "none",
        transition: "box-shadow 0.3s"
      }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", height: 64, gap: 32 }}>
          {/* Wordmark */}
          <a href="#" style={{ display: "flex", alignItems: "center", gap: 10, textDecoration: "none" }}>
            <Logo size={28} />
            <div>
              <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: 16, color: "#fff", letterSpacing: "0.02em", lineHeight: 1 }}>TENET AI</div>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, color: "var(--cyan)", letterSpacing: "0.15em", textTransform: "uppercase" }}>Dev</div>
            </div>
          </a>

          {/* Nav */}
          <nav className="nav-links hide-mobile" style={{ display: "flex", alignItems: "center", gap: 32, marginLeft: "auto" }}>
            <a href="#case-studies" className="nav-link">Case Studies</a>
            <a href="#download" className="nav-link">Download</a>
            <a href={GITHUB} target="_blank" rel="noreferrer" className="nav-link">GitHub</a>
          </nav>

          {/* CTA */}
          <a href="#download" className="btn-primary hide-mobile" style={{ marginLeft: 24, fontSize: 11, padding: "9px 20px" }}>
            ↓ Download Plugin
          </a>

          {/* Mobile menu button */}
          <button
            className="btn-ghost"
            style={{ marginLeft: "auto", display: "none" }}
            onClick={() => setMobileMenu(m => !m)}
            id="hamburger"
          >
            ☰
          </button>
        </div>
        <style>{`@media(max-width:768px){#hamburger{display:flex!important}}`}</style>
        {mobileMenu && (
          <div style={{ padding: "16px 40px 20px", borderTop: "1px solid var(--border)", display: "flex", flexDirection: "column", gap: 16 }}>
            <a href="#case-studies" className="nav-link" onClick={() => setMobileMenu(false)}>Case Studies</a>
            <a href="#download" className="nav-link" onClick={() => setMobileMenu(false)}>Download</a>
            <a href={GITHUB} target="_blank" rel="noreferrer" className="nav-link">GitHub ↗</a>
            <a href="#download" className="btn-primary" style={{ alignSelf: "flex-start", fontSize: 11 }}>Download Plugin</a>
          </div>
        )}
      </header>

      {/* ── HERO ── */}
      <section
        id="hero"
        ref={heroRef}
        className="grid-bg"
        style={{
          minHeight: "100vh",
          display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
          padding: "120px 40px 60px",
          position: "relative", overflow: "hidden"
        }}
      >
        {/* Glow orbs */}
        <div style={{ position: "absolute", top: "20%", left: "10%", width: 400, height: 400, borderRadius: "50%", background: "radial-gradient(circle, rgba(0,212,255,0.06) 0%, transparent 70%)", pointerEvents: "none" }} />
        <div style={{ position: "absolute", bottom: "20%", right: "10%", width: 300, height: 300, borderRadius: "50%", background: "radial-gradient(circle, rgba(230,57,70,0.06) 0%, transparent 70%)", pointerEvents: "none" }} />

        {/* Scan line */}
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: "linear-gradient(90deg, transparent, var(--cyan), transparent)", animation: "scan 4s linear infinite", opacity: 0.3, pointerEvents: "none" }} />

        <div style={{ maxWidth: 800, textAlign: "center", opacity: heroVisible ? 1 : 0, transition: "opacity 0.8s ease" }}>
          {/* Badge */}
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8,
            background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)",
            borderRadius: 20, padding: "6px 16px", marginBottom: 32,
            fontSize: 11, color: "var(--cyan)", letterSpacing: "0.1em",
            animation: heroVisible ? "fadeUp 0.5s ease" : "none"
          }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--cyan)", animation: "pulse-glow 1.5s infinite", display: "inline-block" }} />
            LLM SECURITY MIDDLEWARE — v0.1.0
          </div>

          {/* Logo */}
          <div style={{ marginBottom: 40, animation: heroVisible ? "fadeUp 0.6s ease 0.1s both" : "none" }}>
            <HeroLogo />
          </div>

          {/* Headline */}
          <h1 className="hero-title gradient-text" style={{
            fontSize: 72, fontWeight: 800, lineHeight: 1.05,
            letterSpacing: "-0.02em", marginBottom: 24,
            animation: heroVisible ? "fadeUp 0.7s ease 0.2s both" : "none"
          }}>
            DEFEND YOUR<br />AI APPLICATIONS
          </h1>

          <p style={{
            fontSize: 16, color: "#888", lineHeight: 1.7, maxWidth: 580, margin: "0 auto 40px",
            animation: heroVisible ? "fadeUp 0.7s ease 0.3s both" : "none"
          }}>
            Enterprise-grade security middleware that intercepts, analyzes, and blocks LLM attacks in real-time — before they reach your model.
          </p>

          {/* CTAs */}
          <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap", marginBottom: 64, animation: heroVisible ? "fadeUp 0.7s ease 0.4s both" : "none" }}>
            <a href="#download" className="btn-primary" style={{ fontSize: 13, padding: "14px 28px" }}>
              ↓ Download Plugin
            </a>
            <a href={GITHUB} target="_blank" rel="noreferrer" className="btn-outline" style={{ fontSize: 13, padding: "14px 28px" }}>
              View on GitHub
            </a>
          </div>

          {/* Terminal */}
          <div style={{ animation: heroVisible ? "fadeUp 0.8s ease 0.5s both" : "none" }}>
            <TerminalTicker />
          </div>
        </div>

        {/* ── STATS RIBBON ── */}
        <div style={{
          position: "absolute", bottom: 0, left: 0, right: 0,
          background: "rgba(13,13,15,0.9)",
          borderTop: "1px solid var(--border)",
          backdropFilter: "blur(20px)"
        }}>
          <div className="stats-row" style={{ maxWidth: 1000, margin: "0 auto", display: "flex", alignItems: "stretch" }}>
            {[
              { label: "GitHub Stars", value: stars, suffix: "", live: true },
              { label: "Detection Speed", value: "<10", suffix: "ms", pre: true },
              { label: "ML Accuracy", value: "90", suffix: "%+", pre: true },
              { label: "License", value: "MIT", suffix: "", text: true },
            ].map((s, i) => (
              <div key={i} className="stat-item" style={{ flex: 1 }}>
                {s.live && <div style={{ fontSize: 10, color: "#2ecc71", letterSpacing: "0.1em", marginBottom: 4, display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 5, height: 5, borderRadius: "50%", background: "#2ecc71", display: "inline-block", animation: "pulse-glow 1.5s infinite" }} />
                  LIVE
                </div>}
                <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: 28, color: "var(--cyan)" }}>
                  {s.pre ? s.value + s.suffix : s.text ? s.value : <>{s.value}{s.suffix}</>}
                </div>
                <div style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.1em", textTransform: "uppercase", marginTop: 4 }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CASE STUDIES ── */}
      <section id="case-studies" ref={caseRef} style={{ padding: "100px 40px", background: "var(--bg2)" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ opacity: caseVisible ? 1 : 0, transform: caseVisible ? "translateY(0)" : "translateY(20px)", transition: "all 0.7s ease" }}>
            <div className="section-label">Threat Intelligence</div>
            <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: 40, fontWeight: 800, marginBottom: 12 }}>
              Real-World Breaches<br /><span className="gradient-text">TENET AI Prevents</span>
            </h2>
            <p style={{ color: "var(--muted)", fontSize: 14, marginBottom: 56, maxWidth: 520 }}>
              These incidents happened. The attack vectors are real. TENET AI would have stopped each one.
            </p>
          </div>

          <div className="grid-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
            {caseStudies.map((c, i) => (
              <div key={i} className="case-card" style={{
                opacity: caseVisible ? 1 : 0,
                transform: caseVisible ? "translateY(0)" : "translateY(30px)",
                transition: `all 0.7s ease ${i * 0.1}s`
              }}>
                {/* Header */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                  <div>
                    <div style={{ fontSize: 10, color: "var(--muted)", letterSpacing: "0.12em", marginBottom: 4 }}>{c.date}</div>
                    <h3 style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: 18, color: "#fff" }}>{c.title}</h3>
                  </div>
                  <span style={{ fontSize: 10, color: "var(--crimson)", background: "rgba(230,57,70,0.1)", padding: "4px 8px", borderRadius: 3, letterSpacing: "0.08em", whiteSpace: "nowrap", marginLeft: 12 }}>
                    {c.tag}
                  </span>
                </div>

                {/* Severity */}
                <div style={{ fontSize: 13, color: "var(--crimson)", fontWeight: 600, marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
                  <span>⚠</span> {c.severity}
                </div>

                <p style={{ fontSize: 12, color: "#888", lineHeight: 1.7, marginBottom: 4 }}>{c.description}</p>

                <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 4 }}>
                  <span style={{ color: "#555" }}>Attack vector: </span>{c.attack}
                </div>

                {/* Defense box */}
                <div className="defense-box">
                  <div style={{ fontSize: 10, color: "var(--cyan)", letterSpacing: "0.12em", marginBottom: 6, fontWeight: 600 }}>
                    🛡 TENET AI DEFENSE
                  </div>
                  <div style={{ fontSize: 11, color: "#aaa", lineHeight: 1.6 }}>{c.defense}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section id="how-it-works" ref={howRef} style={{ padding: "100px 40px", background: "var(--bg)" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 64, opacity: howVisible ? 1 : 0, transform: howVisible ? "translateY(0)" : "translateY(20px)", transition: "all 0.7s ease" }}>
            <div className="section-label" style={{ justifyContent: "center" }}>Architecture</div>
            <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: 40, fontWeight: 800 }}>
              How <span className="gradient-text">TENET AI</span> Works
            </h2>
          </div>

          {/* Flow */}
          <div className="grid-4" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 20 }}>
            {steps.map((s, i) => (
              <div key={i} className="step-card" style={{
                opacity: howVisible ? 1 : 0,
                transform: howVisible ? "translateY(0)" : "translateY(30px)",
                transition: `all 0.7s ease ${i * 0.1}s`
              }}>
                {/* Connector line (not last) */}
                {i < steps.length - 1 && (
                  <div style={{ position: "absolute", top: "50%", right: -10, width: 20, height: 1, background: "var(--cyan)", opacity: 0.3 }} className="hide-mobile" />
                )}
                <div style={{ fontSize: 10, color: "var(--cyan)", letterSpacing: "0.15em", marginBottom: 12 }}>{s.num}</div>
                <div style={{ fontSize: 28, marginBottom: 12 }}>{s.icon}</div>
                <h3 style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: 15, marginBottom: 10, color: "var(--cyan)" }}>{s.title}</h3>
                <p style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.6 }}>{s.desc}</p>
              </div>
            ))}
          </div>

          {/* Architecture diagram */}
          <div style={{
            marginTop: 60,
            background: "var(--bg3)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            padding: "32px 40px",
            fontFamily: "'IBM Plex Mono', monospace",
            fontSize: 12,
            color: "#555",
            opacity: howVisible ? 1 : 0,
            transition: "opacity 1s ease 0.5s"
          }}>
            <div style={{ color: "var(--cyan)", fontSize: 11, letterSpacing: "0.1em", marginBottom: 16 }}>// SYSTEM ARCHITECTURE</div>
            <pre style={{ color: "#666", fontSize: 11, lineHeight: 1.8, overflowX: "auto" }}>
{`Your Application ──────────────────────────────────────────────────────────────────┐
                                                                                    │
                          ┌─────────────────────────────────────────┐               │
                          │         TENET AI Security Layer          │               │
                          │                                          │               │
     ┌──────────┐    ┌────┤  Ingest  ──►  Analyzer  ──►  Policy    ├────┐          │
     │ Your App ├───►│    │  Service       Engine        Engine     │    │          │
     └──────────┘    └────┤                                          │    │          │
                          │         Event Queue (Redis)              │    │          │
                          └─────────────────────────────────────────┘    │          │
                                                                          │          │
                               ┌──────────────────┬─────────────────┐   │          │
                               ▼                  ▼                 ▼   │          │
                         ┌──────────┐      ┌──────────┐     ┌──────────┐│          │
                         │  OpenAI  │      │ Anthropic │     │  Ollama  ││          │
                         │  GPT-4   │      │  Claude  │     │  Local   ││          │
                         └──────────┘      └──────────┘     └──────────┘│          │
                                                                          │          │
                               ┌──────────────────────────────────────┐  │          │
                               │          SOC Dashboard (React)        │  │          │
                               │     Real-time alerts + analytics      │  │          │
                               └──────────────────────────────────────┘  │          │
                                                                          └──────────┘`}
            </pre>
          </div>
        </div>
      </section>

      {/* ── DOWNLOAD ── */}
      <section id="download" ref={dlRef} style={{ padding: "100px 40px", background: "var(--bg2)" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 64, opacity: dlVisible ? 1 : 0, transform: dlVisible ? "translateY(0)" : "translateY(20px)", transition: "all 0.7s ease" }}>
            <div className="section-label" style={{ justifyContent: "center" }}>Integration</div>
            <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: 40, fontWeight: 800, marginBottom: 12 }}>
              Download & <span className="gradient-text">Integrate</span>
            </h2>
            <p style={{ color: "var(--muted)", fontSize: 14, maxWidth: 480, margin: "0 auto" }}>
              Drop TENET AI into your stack in minutes. Works with any LLM provider.
            </p>
          </div>

          <div className="grid-4" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 20 }}>
            {downloads.map((d, i) => (
              <div key={i} className="dl-card" style={{
                opacity: dlVisible ? 1 : 0,
                transform: dlVisible ? "translateY(0)" : "translateY(30px)",
                transition: `all 0.7s ease ${i * 0.1}s`
              }}>
                <div style={{ fontSize: 36, marginBottom: 16 }}>{d.icon}</div>
                <h3 style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: 18, marginBottom: 6, color: "#fff" }}>{d.title}</h3>
                <p style={{ fontSize: 12, color: "var(--muted)", marginBottom: 20, lineHeight: 1.5 }}>{d.subtitle}</p>

                {/* Install badge */}
                <div style={{
                  background: "#0a0a0c", border: "1px solid rgba(0,212,255,0.15)",
                  borderRadius: 4, padding: "7px 12px",
                  fontSize: 11, color: "var(--cyan)", marginBottom: 20,
                  fontFamily: "'IBM Plex Mono', monospace"
                }}>
                  $ {d.badge}
                </div>

                {/* Features */}
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 24 }}>
                  {d.features.map((f, j) => (
                    <span key={j} className="feature-tag">✓ {f}</span>
                  ))}
                </div>

                <a href={GITHUB} target="_blank" rel="noreferrer" className="btn-primary" style={{ width: "100%", justifyContent: "center", fontSize: 11 }}>
                  {d.btn}
                </a>
              </div>
            ))}
          </div>

          {/* Quick start code block */}
          <div style={{
            marginTop: 60,
            background: "#0a0a0c",
            border: "1px solid rgba(0,212,255,0.15)",
            borderRadius: 8,
            overflow: "hidden",
            opacity: dlVisible ? 1 : 0,
            transition: "opacity 0.8s ease 0.5s"
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 20px", borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(255,255,255,0.02)" }}>
              <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#e63946" }} />
              <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ffb703" }} />
              <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#2ecc71" }} />
              <span style={{ marginLeft: 12, fontSize: 11, color: "#555" }}>quick_start.py</span>
            </div>
            <pre style={{ padding: "24px 28px", fontSize: 12, lineHeight: 1.8, overflowX: "auto", color: "#888" }}>
              <span style={{ color: "#569cd6" }}>import</span> <span style={{ color: "var(--cyan)" }}>requests</span>{"\n"}
              {"\n"}
              <span style={{ color: "#555" }}># 1. Send prompt to TENET AI</span>{"\n"}
              result = requests.<span style={{ color: "#dcdcaa" }}>post</span>(<span style={{ color: "#ce9178" }}>"http://localhost:8000/v1/events/llm"</span>,{"\n"}
              {"    "}headers={"{"}<span style={{ color: "#ce9178" }}>"X-API-Key"</span>: <span style={{ color: "#ce9178" }}>"your-key"</span>{"}"},{"\n"}
              {"    "}json={"{"}<span style={{ color: "#ce9178" }}>"source_type"</span>: <span style={{ color: "#ce9178" }}>"chat"</span>, <span style={{ color: "#ce9178" }}>"prompt"</span>: user_prompt{"}"}){"\n"}
              {"\n"}
              <span style={{ color: "#555" }}># 2. Check verdict</span>{"\n"}
              <span style={{ color: "#c586c0" }}>if</span> result.json()[<span style={{ color: "#ce9178" }}>"blocked"</span>]:{"\n"}
              {"    "}<span style={{ color: "#dcdcaa" }}>print</span>(<span style={{ color: "#ce9178" }}>"⛔ Request blocked"</span>){"\n"}
              <span style={{ color: "#c586c0" }}>else</span>:{"\n"}
              {"    "}<span style={{ color: "#555" }}># Safe — forward to ANY LLM</span>{"\n"}
              {"    "}response = your_llm.<span style={{ color: "#dcdcaa" }}>complete</span>(user_prompt)
            </pre>
          </div>
        </div>
      </section>

      {/* ── FINAL CTA ── */}
      <section
        ref={ctaRef}
        style={{
          padding: "120px 40px",
          background: "var(--bg)",
          textAlign: "center",
          position: "relative",
          overflow: "hidden"
        }}
      >
        <div style={{ position: "absolute", inset: 0, background: "radial-gradient(ellipse at center, rgba(0,212,255,0.05) 0%, transparent 70%)", pointerEvents: "none" }} />
        <div style={{
          maxWidth: 640, margin: "0 auto", position: "relative",
          opacity: ctaVisible ? 1 : 0,
          transform: ctaVisible ? "translateY(0)" : "translateY(30px)",
          transition: "all 0.8s ease"
        }}>
          <div style={{ fontSize: 48, marginBottom: 24 }}>🛡️</div>
          <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: 44, fontWeight: 800, marginBottom: 16 }}>
            Start Protecting Your<br /><span className="gradient-text">AI Applications Today</span>
          </h2>
          <p style={{ color: "var(--muted)", fontSize: 14, marginBottom: 12 }}>
            Self-hosted. Open source. Battle-tested on real attack patterns.
          </p>
          <div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap", marginBottom: 48 }}>
            {["MIT Licensed", "No vendor lock-in", "Self-hosted", "LLM agnostic"].map((t, i) => (
              <span key={i} style={{ fontSize: 11, color: "var(--cyan)", background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)", padding: "4px 12px", borderRadius: 20 }}>✓ {t}</span>
            ))}
          </div>
          <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
            <a href="#download" className="btn-primary" style={{ fontSize: 14, padding: "15px 32px" }}>↓ Download Plugin</a>
            <a href={GITHUB} target="_blank" rel="noreferrer" className="btn-outline" style={{ fontSize: 14, padding: "15px 32px" }}>⭐ Star on GitHub</a>
          </div>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer style={{ borderTop: "1px solid var(--border)", padding: "40px 40px", background: "var(--bg2)" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Logo size={22} />
            <span style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: 14, color: "#fff" }}>TENET AI Dev</span>
          </div>

          <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
            {[
              ["GitHub", GITHUB],
              ["Contributing", `${GITHUB}/blob/main/CONTRIBUTING.md`],
              ["Security", `${GITHUB}/blob/main/SECURITY.md`],
              ["Contact", "mailto:saviodsouza8a@gmail.com"]
            ].map(([label, href]) => (
              <a key={label} href={href} target="_blank" rel="noreferrer" className="nav-link">{label}</a>
            ))}
          </div>

          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 4 }}>
              Built by <span style={{ color: "var(--cyan)" }}>Savio D'souza</span> | Open Source Security for AI
            </div>
            <div style={{ fontSize: 10, color: "#444" }}>© 2026 TENET AI Dev. MIT Licensed.</div>
          </div>
        </div>
      </footer>
    </>
  );
}
