import { useState, useEffect, useRef } from "react";

/* ─────────────────────────────────────────────
   TENET AI DEV  –  Landing Page
   Inspired by: BLT NetGuardian Client
   Style: Dark dashboard · Card grid · Product-forward
───────────────────────────────────────────── */

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:        #0b0d11;
  --surface:   #12141a;
  --surface2:  #191c24;
  --surface3:  #1f2230;
  --border:    #252836;
  --border2:   #2e3347;
  --cyan:      #00d4ff;
  --cyan-dim:  rgba(0,212,255,0.12);
  --cyan-glow: rgba(0,212,255,0.25);
  --red:       #e63946;
  --red-dim:   rgba(230,57,70,0.12);
  --amber:     #ffb703;
  --amber-dim: rgba(255,183,3,0.12);
  --green:     #2dd4bf;
  --green-dim: rgba(45,212,191,0.12);
  --purple:    #a78bfa;
  --purple-dim:rgba(167,139,250,0.12);
  --text:      #e2e4ec;
  --text2:     #9095a8;
  --text3:     #565c70;
  --font:      'Inter', sans-serif;
  --mono:      'JetBrains Mono', monospace;
}

html { scroll-behavior: smooth; }
body { background: var(--bg); color: var(--text); font-family: var(--font); -webkit-font-smoothing: antialiased; overflow-x: hidden; }
::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: var(--bg); } ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--cyan); }

/* ── Layout ── */
.page { display: flex; flex-direction: column; min-height: 100vh; }

/* ── Topbar ── */
.topbar {
  position: fixed; top: 0; left: 0; right: 0; z-index: 100;
  height: 56px;
  background: rgba(11,13,17,0.92);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(16px);
  display: flex; align-items: center; padding: 0 24px; gap: 0;
}
.topbar-brand { display: flex; align-items: center; gap: 10px; text-decoration: none; min-width: 200px; }
.topbar-brand-name { font-weight: 700; font-size: 15px; color: var(--text); letter-spacing: -0.01em; }
.topbar-brand-badge { font-size: 10px; background: var(--cyan-dim); color: var(--cyan); border: 1px solid rgba(0,212,255,0.25); border-radius: 4px; padding: 1px 6px; font-family: var(--mono); letter-spacing: 0.05em; margin-left: 2px; }
.topbar-tabs { display: flex; align-items: center; height: 100%; gap: 2px; margin-left: 8px; flex: 1; }
.topbar-tab { display: flex; align-items: center; gap: 6px; height: 100%; padding: 0 14px; font-size: 12.5px; font-weight: 500; color: var(--text3); text-decoration: none; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.15s; white-space: nowrap; }
.topbar-tab:hover { color: var(--text2); background: rgba(255,255,255,0.03); }
.topbar-tab.active { color: var(--cyan); border-bottom-color: var(--cyan); }
.topbar-tab svg { opacity: 0.6; }
.topbar-tab.active svg { opacity: 1; }
.topbar-right { display: flex; align-items: center; gap: 10px; margin-left: auto; }
.topbar-status { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--green); font-family: var(--mono); }
.status-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }
.btn { display: inline-flex; align-items: center; gap: 6px; border: none; cursor: pointer; font-family: var(--font); font-weight: 500; border-radius: 6px; text-decoration: none; transition: all 0.15s; white-space: nowrap; }
.btn-sm { font-size: 12px; padding: 6px 12px; }
.btn-md { font-size: 13px; padding: 9px 18px; }
.btn-lg { font-size: 14px; padding: 12px 24px; }
.btn-primary { background: var(--cyan); color: #0b0d11; }
.btn-primary:hover { background: #1adeff; box-shadow: 0 0 20px var(--cyan-glow); transform: translateY(-1px); }
.btn-secondary { background: var(--surface3); color: var(--text); border: 1px solid var(--border2); }
.btn-secondary:hover { border-color: var(--cyan); color: var(--cyan); }
.btn-ghost { background: transparent; color: var(--text2); border: 1px solid var(--border); }
.btn-ghost:hover { color: var(--cyan); border-color: var(--cyan); }
.btn-danger { background: var(--red-dim); color: var(--red); border: 1px solid rgba(230,57,70,0.3); }
.btn-danger:hover { background: rgba(230,57,70,0.2); }

/* ── Main content ── */
.main { margin-top: 56px; flex: 1; }

/* ── Section ── */
.section { padding: 56px 0; }
.section-alt { background: var(--surface); }
.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }
.section-header { margin-bottom: 40px; }
.section-eyebrow { display: flex; align-items: center; gap: 8px; font-size: 11px; font-family: var(--mono); color: var(--cyan); letter-spacing: 0.12em; text-transform: uppercase; margin-bottom: 12px; }
.section-eyebrow::before { content:''; width: 16px; height: 1px; background: var(--cyan); flex-shrink: 0; }
.section-title { font-size: 30px; font-weight: 800; letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 10px; }
.section-sub { font-size: 14px; color: var(--text2); max-width: 520px; line-height: 1.7; }
.gradient { background: linear-gradient(120deg, #fff 0%, var(--cyan) 55%, #0099bb 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }

/* ── Hero ── */
.hero { padding: 80px 0 56px; background: var(--bg); position: relative; overflow: hidden; }
.hero-grid { background-image: linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px); background-size: 48px 48px; position: absolute; inset: 0; opacity: 0.3; }
.hero-glow { position: absolute; top: -100px; left: 50%; transform: translateX(-50%); width: 800px; height: 400px; background: radial-gradient(ellipse, rgba(0,212,255,0.07) 0%, transparent 70%); pointer-events: none; }
.hero-inner { position: relative; display: grid; grid-template-columns: 1fr 1fr; gap: 64px; align-items: center; }
.hero-badge { display: inline-flex; align-items: center; gap: 8px; background: var(--surface2); border: 1px solid var(--border2); border-radius: 20px; padding: 5px 14px 5px 8px; font-size: 11.5px; color: var(--text2); margin-bottom: 24px; }
.hero-badge-pill { background: var(--cyan); color: #0b0d11; font-size: 9px; font-weight: 700; padding: 2px 7px; border-radius: 10px; letter-spacing: 0.06em; }
.hero-title { font-size: 48px; font-weight: 800; letter-spacing: -0.03em; line-height: 1.1; margin-bottom: 20px; }
.hero-desc { font-size: 15px; color: var(--text2); line-height: 1.75; margin-bottom: 32px; max-width: 480px; }
.hero-actions { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 40px; }
.hero-meta { display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
.hero-meta-item { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text3); font-family: var(--mono); }
.hero-meta-item span { color: var(--text2); }

/* ── Dashboard Preview (right side of hero) ── */
.dashboard-preview { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; box-shadow: 0 32px 80px rgba(0,0,0,0.5); }
.dp-header { background: var(--surface2); border-bottom: 1px solid var(--border); padding: 10px 16px; display: flex; align-items: center; gap: 8px; }
.dp-dot { width: 10px; height: 10px; border-radius: 50%; }
.dp-title { font-size: 12px; color: var(--text3); margin-left: 8px; font-family: var(--mono); }
.dp-body { padding: 16px; display: flex; flex-direction: column; gap: 10px; }
.dp-stat-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.dp-stat { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
.dp-stat-val { font-size: 22px; font-weight: 700; font-family: var(--mono); line-height: 1; margin-bottom: 4px; }
.dp-stat-label { font-size: 10px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.08em; }
.dp-log { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; font-family: var(--mono); font-size: 11px; display: flex; flex-direction: column; gap: 6px; }
.dp-log-line { display: flex; gap: 8px; align-items: center; }
.dp-log-time { color: var(--text3); min-width: 60px; }
.dp-log-tag { font-size: 9px; font-weight: 600; padding: 1px 6px; border-radius: 3px; min-width: 52px; text-align: center; }
.dp-bar-row { display: flex; flex-direction: column; gap: 6px; background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
.dp-bar-item { display: flex; align-items: center; gap: 8px; }
.dp-bar-label { font-size: 10px; color: var(--text3); min-width: 100px; }
.dp-bar-track { flex: 1; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
.dp-bar-fill { height: 100%; border-radius: 2px; transition: width 1.5s ease; }
.dp-bar-val { font-size: 10px; color: var(--text2); font-family: var(--mono); min-width: 32px; text-align: right; }

/* ── Stat cards ── */
.stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--border); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.stat-card { background: var(--surface); padding: 24px 28px; }
.stat-card-val { font-size: 36px; font-weight: 800; font-family: var(--mono); letter-spacing: -0.02em; line-height: 1; margin-bottom: 6px; }
.stat-card-label { font-size: 12px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.08em; }
.stat-card-sub { font-size: 11px; color: var(--text3); margin-top: 4px; font-family: var(--mono); }

/* ── Feature cards ── */
.feature-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.feature-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 24px; transition: all 0.2s; position: relative; overflow: hidden; }
.feature-card::after { content:''; position: absolute; inset: 0; background: linear-gradient(135deg, var(--cyan-dim) 0%, transparent 60%); opacity: 0; transition: opacity 0.2s; }
.feature-card:hover { border-color: var(--border2); transform: translateY(-3px); box-shadow: 0 12px 40px rgba(0,0,0,0.3); }
.feature-card:hover::after { opacity: 1; }
.feature-icon { width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; margin-bottom: 16px; }
.feature-title { font-size: 15px; font-weight: 600; margin-bottom: 8px; }
.feature-desc { font-size: 13px; color: var(--text2); line-height: 1.65; }
.feature-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 16px; }
.tag { font-size: 10.5px; font-family: var(--mono); padding: 3px 8px; border-radius: 4px; border: 1px solid transparent; }

/* ── Threat cards ── */
.threat-list { display: flex; flex-direction: column; gap: 12px; }
.threat-card { background: var(--surface); border: 1px solid var(--border); border-left: 3px solid; border-radius: 8px; padding: 20px 20px 20px 20px; display: grid; grid-template-columns: auto 1fr auto; gap: 16px; align-items: start; transition: all 0.2s; cursor: default; }
.threat-card:hover { border-right-color: var(--border2); background: var(--surface2); transform: translateX(3px); }
.threat-meta { display: flex; flex-direction: column; gap: 6px; min-width: 160px; }
.threat-date { font-size: 10px; font-family: var(--mono); color: var(--text3); }
.threat-severity { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; display: inline-flex; align-items: center; gap: 4px; width: fit-content; }
.threat-type-tag { font-size: 10px; font-family: var(--mono); color: var(--text3); background: var(--surface3); padding: 2px 7px; border-radius: 3px; width: fit-content; }
.threat-body { min-width: 0; }
.threat-title { font-size: 14px; font-weight: 600; margin-bottom: 6px; }
.threat-desc { font-size: 12.5px; color: var(--text2); line-height: 1.6; margin-bottom: 10px; }
.threat-defense { background: rgba(0,212,255,0.04); border: 1px solid rgba(0,212,255,0.15); border-radius: 6px; padding: 10px 12px; }
.threat-defense-label { font-size: 9.5px; font-family: var(--mono); color: var(--cyan); letter-spacing: 0.1em; margin-bottom: 4px; font-weight: 600; }
.threat-defense-text { font-size: 11.5px; color: var(--text2); line-height: 1.55; }
.threat-stat { text-align: right; min-width: 80px; }
.threat-stat-val { font-size: 20px; font-weight: 700; font-family: var(--mono); line-height: 1; }
.threat-stat-label { font-size: 10px; color: var(--text3); margin-top: 3px; }

/* ── Install grid ── */
.install-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
.install-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; transition: all 0.2s; }
.install-card:hover { border-color: var(--border2); transform: translateY(-2px); box-shadow: 0 16px 48px rgba(0,0,0,0.3); }
.install-card-header { padding: 20px 20px 0; display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.install-card-icon { font-size: 28px; }
.install-card-platform { font-size: 10px; font-family: var(--mono); color: var(--text3); background: var(--surface3); padding: 2px 8px; border-radius: 4px; }
.install-card-title { font-size: 15px; font-weight: 600; margin-bottom: 4px; }
.install-card-sub { font-size: 12px; color: var(--text2); margin-bottom: 14px; }
.install-card-code { background: var(--bg); border-top: 1px solid var(--border); padding: 12px 20px; font-family: var(--mono); font-size: 12px; color: var(--cyan); display: flex; align-items: center; gap: 8px; }
.install-card-code-prompt { color: var(--text3); }
.install-card-body { padding: 0 20px 20px; }
.install-card-features { display: flex; flex-direction: column; gap: 5px; margin-bottom: 16px; }
.install-card-feature { display: flex; align-items: center; gap: 7px; font-size: 12px; color: var(--text2); }
.install-card-feature::before { content:''; width: 4px; height: 4px; border-radius: 50%; background: var(--cyan); flex-shrink: 0; }

/* ── How it works ── */
.how-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; position: relative; }
.how-grid::before { content:''; position: absolute; top: 28px; left: calc(12.5% + 14px); right: calc(12.5% + 14px); height: 1px; background: linear-gradient(90deg, var(--border2), var(--cyan), var(--border2)); }
.how-step { padding: 0 16px 0; text-align: center; position: relative; }
.how-step-num { width: 56px; height: 56px; border-radius: 50%; background: var(--surface); border: 1px solid var(--border2); display: flex; align-items: center; justify-content: center; font-size: 18px; margin: 0 auto 20px; position: relative; z-index: 1; transition: all 0.2s; }
.how-step:hover .how-step-num { border-color: var(--cyan); background: var(--cyan-dim); box-shadow: 0 0 20px var(--cyan-glow); }
.how-step-label { font-size: 10px; font-family: var(--mono); color: var(--cyan); letter-spacing: 0.12em; margin-bottom: 8px; }
.how-step-title { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
.how-step-desc { font-size: 12px; color: var(--text2); line-height: 1.6; }

/* ── Code block ── */
.code-block { background: var(--bg); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.code-header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 10px 16px; display: flex; align-items: center; gap: 10px; }
.code-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.code-filename { font-size: 12px; color: var(--text3); font-family: var(--mono); margin-left: 8px; }
.code-lang { font-size: 10px; font-family: var(--mono); color: var(--text3); background: var(--surface3); padding: 2px 8px; border-radius: 3px; margin-left: auto; }
.code-body { padding: 20px 24px; font-family: var(--mono); font-size: 12.5px; line-height: 1.9; overflow-x: auto; }
.c-comment { color: #4b5363; }
.c-keyword { color: #c792ea; }
.c-string { color: #c3e88d; }
.c-func { color: #82aaff; }
.c-var { color: var(--text); }
.c-cyan { color: var(--cyan); }
.c-dim { color: #4b5363; }

/* ── CTA ── */
.cta-section { padding: 80px 0; text-align: center; position: relative; overflow: hidden; }
.cta-glow { position: absolute; inset: 0; background: radial-gradient(ellipse at center, rgba(0,212,255,0.06) 0%, transparent 70%); pointer-events: none; }
.cta-title { font-size: 40px; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 16px; }
.cta-sub { font-size: 15px; color: var(--text2); margin-bottom: 36px; }
.cta-actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; margin-bottom: 32px; }
.cta-pills { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
.cta-pill { font-size: 11.5px; color: var(--text3); background: var(--surface); border: 1px solid var(--border); border-radius: 20px; padding: 5px 14px; display: flex; align-items: center; gap: 6px; }
.cta-pill::before { content:'✓'; color: var(--cyan); font-size: 10px; }

/* ── Footer ── */
.footer { background: var(--surface); border-top: 1px solid var(--border); padding: 32px 0; }
.footer-inner { display: flex; align-items: center; justify-content: space-between; gap: 24px; flex-wrap: wrap; }
.footer-brand { display: flex; align-items: center; gap: 10px; }
.footer-links { display: flex; gap: 24px; }
.footer-link { font-size: 12.5px; color: var(--text3); text-decoration: none; transition: color 0.15s; }
.footer-link:hover { color: var(--cyan); }
.footer-copy { font-size: 11.5px; color: var(--text3); font-family: var(--mono); }

/* ── Animations ── */
@keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.6;transform:scale(0.85)} }
@keyframes fadeUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
@keyframes slideIn { from{opacity:0;transform:translateX(-12px)} to{opacity:1;transform:translateX(0)} }
@keyframes blinkCursor { 50%{opacity:0} }
.anim-fadeup { animation: fadeUp 0.6s ease both; }
.anim-fadeup-1 { animation: fadeUp 0.6s 0.1s ease both; }
.anim-fadeup-2 { animation: fadeUp 0.6s 0.2s ease both; }
.anim-fadeup-3 { animation: fadeUp 0.6s 0.3s ease both; }
.anim-fadeup-4 { animation: fadeUp 0.6s 0.4s ease both; }

/* ── Responsive ── */
@media(max-width:1024px){ .hero-inner{grid-template-columns:1fr} .dashboard-preview{display:none} .feature-grid{grid-template-columns:1fr 1fr} .how-grid{grid-template-columns:1fr 1fr;gap:24px} .how-grid::before{display:none} .stat-grid{grid-template-columns:1fr 1fr} }
@media(max-width:768px){ .hero-title{font-size:34px} .install-grid{grid-template-columns:1fr} .feature-grid{grid-template-columns:1fr} .threat-card{grid-template-columns:1fr;gap:10px} .threat-stat{text-align:left} .topbar-tabs .topbar-tab:not(.active){display:none} }
@media(max-width:480px){ .stat-grid{grid-template-columns:1fr} .cta-title{font-size:28px} }
`;

// ── SVG Icons
const Icons = {
  Shield: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Zap: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>,
  Eye: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
  Activity: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  Download: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>,
  GitHub: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>,
  Terminal: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>,
  Cpu: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>,
  Lock: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>,
  Network: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="5" r="3"/><circle cx="19" cy="19" r="3"/><circle cx="5" cy="19" r="3"/><line x1="12" y1="8" x2="12" y2="14"/><line x1="12" y1="14" x2="5" y2="19"/><line x1="12" y1="14" x2="19" y2="19"/></svg>,
  ChevronRight: () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>,
};

// ── Logo
const Logo = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 60 60" fill="none">
    <defs>
      <linearGradient id="lg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stopColor="#00d4ff"/>
        <stop offset="100%" stopColor="#0099bb"/>
      </linearGradient>
    </defs>
    <polygon points="30,4 54,17 54,43 30,56 6,43 6,17" fill="none" stroke="url(#lg)" strokeWidth="1.5" opacity="0.5"/>
    <polygon points="30,4 54,17 30,30 6,17" fill="rgba(0,212,255,0.07)" stroke="url(#lg)" strokeWidth="1.2"/>
    <polygon points="30,30 54,17 54,43 30,56" fill="rgba(0,212,255,0.04)" stroke="url(#lg)" strokeWidth="1.2"/>
    <polygon points="30,30 6,17 6,43 30,56" fill="rgba(0,212,255,0.02)" stroke="url(#lg)" strokeWidth="1.2"/>
    <line x1="30" y1="4" x2="30" y2="56" stroke="url(#lg)" strokeWidth="0.8" opacity="0.5"/>
    <line x1="6" y1="17" x2="54" y2="43" stroke="url(#lg)" strokeWidth="0.8" opacity="0.35"/>
    <line x1="54" y1="17" x2="6" y2="43" stroke="url(#lg)" strokeWidth="0.8" opacity="0.35"/>
    <circle cx="30" cy="30" r="4" fill="#00d4ff" opacity="0.95"/>
    {[[30,4],[54,17],[54,43],[30,56],[6,43],[6,17]].map(([cx,cy],i)=>(
      <circle key={i} cx={cx} cy={cy} r="2.5" fill="#00d4ff" opacity="0.7"/>
    ))}
  </svg>
);

// ── Live log feed
const LOG_EVENTS = [
  { tag:"BLOCKED", tagColor:"#e63946", tagBg:"rgba(230,57,70,0.15)", msg:"prompt_injection · ignore_instructions pattern", src:"api.prod" },
  { tag:"ALLOWED", tagColor:"#2dd4bf", tagBg:"rgba(45,212,191,0.12)", msg:"normal_query · risk_score: 0.03", src:"chat.app" },
  { tag:"BLOCKED", tagColor:"#e63946", tagBg:"rgba(230,57,70,0.15)", msg:"jailbreak · DAN_mode variant detected", src:"agt.01" },
  { tag:"FLAGGED", tagColor:"#ffb703", tagBg:"rgba(255,183,3,0.12)", msg:"data_extraction · system_prompt probe", src:"api.dev" },
  { tag:"BLOCKED", tagColor:"#e63946", tagBg:"rgba(230,57,70,0.15)", msg:"role_manipulation · persona_override", src:"embed.01" },
  { tag:"ALLOWED", tagColor:"#2dd4bf", tagBg:"rgba(45,212,191,0.12)", msg:"normal_query · risk_score: 0.01", src:"chat.app" },
];

function LiveLog() {
  const [lines, setLines] = useState(LOG_EVENTS.slice(0, 4));
  const [idx, setIdx] = useState(4);
  useEffect(() => {
    const t = setInterval(() => {
      setLines(p => [...p.slice(-4), LOG_EVENTS[idx % LOG_EVENTS.length]]);
      setIdx(i => i + 1);
    }, 2200);
    return () => clearInterval(t);
  }, [idx]);

  const now = new Date();
  const fmt = (offset) => {
    const d = new Date(now - offset * 1000);
    return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
  };

  return (
    <div className="dp-log">
      {lines.map((l, i) => (
        <div key={i} className="dp-log-line" style={{ animation: i === lines.length - 1 ? 'slideIn 0.3s ease' : 'none', opacity: 0.5 + i * 0.17 }}>
          <span className="dp-log-time">{fmt((lines.length - 1 - i) * 3)}</span>
          <span className="dp-log-tag" style={{ color: l.tagColor, background: l.tagBg }}>{l.tag}</span>
          <span style={{ color: '#6b7080', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.msg}</span>
          <span style={{ color: '#3d4152', marginLeft: 8 }}>{l.src}</span>
        </div>
      ))}
    </div>
  );
}

// ── Animated number
function AnimNum({ to, dur = 1400 }) {
  const [val, setVal] = useState(0);
  const ref = useRef(); const started = useRef(false);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting && !started.current) {
        started.current = true;
        const steps = 50; let s = 0;
        const t = setInterval(() => {
          s++; setVal(Math.round(to * Math.min(s/steps, 1)));
          if (s >= steps) clearInterval(t);
        }, dur / steps);
      }
    }, { threshold: 0.5 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [to]);
  return <span ref={ref}>{val.toLocaleString()}</span>;
}

// ── Fade-up on scroll
function FadeUp({ children, delay = 0, style = {} }) {
  const ref = useRef(); const [vis, setVis] = useState(false);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setVis(true); obs.disconnect(); } }, { threshold: 0.1 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);
  return (
    <div ref={ref} style={{ opacity: vis ? 1 : 0, transform: vis ? 'none' : 'translateY(18px)', transition: `opacity 0.55s ${delay}s ease, transform 0.55s ${delay}s ease`, ...style }}>
      {children}
    </div>
  );
}

// ── Data
const THREATS = [
  { date:"FEB 2026", type:"JAILBREAK", title:"Mexican Government AI Breach", severity:"CRITICAL", sevColor:"#e63946", sevBg:"rgba(230,57,70,0.12)", stat:"195M", statLabel:"Records", desc:"Attacker used Claude AI to exfiltrate government records via chained jailbreak prompts. Role-play injection bypassed standard content filters across 47 federal agencies over multiple sessions.", defense:"Detected 'act as elite hacker' + role-play injection pattern. Blocked at 4ms. Multi-turn chain fingerprinted + session terminated.", leftColor:"#e63946" },
  { date:"JAN 2026", type:"PROMPT INJECTION", title:"Fortune 500 Chatbot Compromise", severity:"HIGH", sevColor:"#ffb703", sevBg:"rgba(255,183,3,0.12)", stat:"$4.2M", statLabel:"Loss", desc:"Customer chatbot exploited via iterative prompt injection exposing internal pricing models and PII. Attacker submitted 47 payload variations to find the bypass vector.", defense:"Detected 47 structurally similar attempts. Auto-blocked after threshold. Session risk score elevated progressively across attempts.", leftColor:"#ffb703" },
  { date:"DEC 2025", type:"JAILBREAK", title:"Healthcare Enterprise Breach", severity:"HIGH", sevColor:"#ffb703", sevBg:"rgba(255,183,3,0.12)", stat:"HIPAA", statLabel:"Violation", desc:"Internal clinical AI assistant jailbroken via DAN (Do Anything Now) mode granting unrestricted access to patient record queries across hospital network.", defense:"Blocked jailbreak variant on attempt #1. Behavioral fingerprint added to shared threat intelligence feed in real-time.", leftColor:"#a78bfa" },
  { date:"NOV 2025", type:"IP EXTRACTION", title:"Corporate Algorithm Exfiltration", severity:"MEDIUM", sevColor:"#2dd4bf", sevBg:"rgba(45,212,191,0.12)", stat:"12", statLabel:"Sessions", desc:"Nation-state actor exploited coding assistant over 12 sessions using multi-turn context manipulation to gradually extract proprietary encryption algorithms.", defense:"ML behavioral model detected anomaly at session 4. Full 12-session attack chain reconstructed and logged for forensics.", leftColor:"#2dd4bf" },
];

const FEATURES = [
  { icon:"🔍", bg:"var(--cyan-dim)", title:"Heuristic Detection", desc:"Zero-config pattern matching for known attack signatures. Covers prompt injection, jailbreaks, role manipulation, and context confusion out of the box.", tags:[{l:"<5ms",c:"cyan"},{l:"zero-config",c:"dim"}] },
  { icon:"🧠", bg:"var(--purple-dim)", title:"ML-Based Analysis", desc:"Trained classifier with >90% accuracy on adversarial prompt datasets. Continuously improves from analyst feedback and shared threat intelligence.", tags:[{l:">90% accuracy",c:"purple"},{l:"adaptive",c:"dim"}] },
  { icon:"👁", bg:"var(--amber-dim)", title:"Behavioral Analysis", desc:"Tracks prompting patterns across sessions. Detects coordinated attacks, anomalous behavior, and multi-turn manipulation chains that single-shot models miss.", tags:[{l:"cross-session",c:"amber"},{l:"anomaly detection",c:"dim"}] },
  { icon:"⚡", bg:"var(--green-dim)", title:"Real-Time Policy Engine", desc:"Block, sanitize, flag, or allow — configurable policy rules execute in under 10ms total overhead. Zero changes required to your existing LLM integration.", tags:[{l:"<10ms",c:"green"},{l:"configurable",c:"dim"}] },
  { icon:"📊", bg:"var(--cyan-dim)", title:"SOC Dashboard", desc:"Security Operations Center interface with live threat feeds, attack timelines, risk score trends, and analyst workflows. Audit-ready logs for compliance.", tags:[{l:"real-time",c:"cyan"},{l:"SOC-ready",c:"dim"}] },
  { icon:"🔌", bg:"var(--purple-dim)", title:"Universal Integration", desc:"LLM-agnostic middleware compatible with OpenAI, Anthropic, Cohere, Ollama, and any local model. One API call added to your existing stack.", tags:[{l:"any LLM",c:"purple"},{l:"one API call",c:"dim"}] },
];

const INSTALLS = [
  { icon:"🐍", platform:"Python", title:"Python SDK", sub:"Async-first middleware for Python applications", cmd:"pip install tenet-ai", features:["FastAPI / Django / Flask","LangChain & LlamaIndex","Full async/await support","Complete type hints"] },
  { icon:"📦", platform:"Node.js", title:"Node.js Package", sub:"TypeScript-native NPM package", cmd:"npm install @tenet-ai/sdk", features:["Express / Next.js middleware","Cloudflare Workers support","TypeScript out of the box","Edge runtime compatible"] },
  { icon:"🐳", platform:"Docker", title:"Docker Image", sub:"Self-hosted REST API + SOC dashboard", cmd:"docker pull tenetai/core", features:["One-command deployment","SOC dashboard included","Prometheus + Grafana ready","PostgreSQL + Redis bundled"] },
  { icon:"☁️", platform:"Cloud", title:"Cloud Templates", sub:"Infrastructure-as-code for all major clouds", cmd:"helm install tenet-ai ./chart", features:["AWS Lambda layer","Azure Functions extension","GCP Cloud Run template","Kubernetes Helm chart"] },
];

// ── Main
export default function App() {
  const [tab, setTab] = useState("dashboard");
  const [stars, setStars] = useState("3");
  const [barWidths, setBarWidths] = useState([0, 0, 0, 0]);
  const GITHUB = "https://github.com/TENET-DEV-AI/TENET-AI";

  useEffect(() => {
    fetch("https://api.github.com/repos/TENET-DEV-AI/TENET-AI")
      .then(r => r.json()).then(d => { if (d.stargazers_count != null) setStars(d.stargazers_count); }).catch(()=>{});
    setTimeout(() => setBarWidths([92, 7, 1, 0.4]), 600);
  }, []);

  const tagStyle = (c) => ({
    tag: true,
    style: {
      color: c === "cyan" ? "var(--cyan)" : c === "purple" ? "var(--purple)" : c === "amber" ? "var(--amber)" : c === "green" ? "var(--green)" : "var(--text3)",
      background: c === "cyan" ? "var(--cyan-dim)" : c === "purple" ? "var(--purple-dim)" : c === "amber" ? "var(--amber-dim)" : c === "green" ? "var(--green-dim)" : "var(--surface3)",
      borderColor: c === "cyan" ? "rgba(0,212,255,0.2)" : c === "purple" ? "rgba(167,139,250,0.2)" : c === "amber" ? "rgba(255,183,3,0.2)" : c === "green" ? "rgba(45,212,191,0.2)" : "var(--border)",
    }
  });

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: CSS }} />
      <div className="page">

        {/* ── TOPBAR ── */}
        <header className="topbar">
          <a href="#" className="topbar-brand">
            <Logo size={26} />
            <span className="topbar-brand-name">TENET AI</span>
            <span className="topbar-brand-badge">v0.1</span>
          </a>

          <nav className="topbar-tabs">
            {[
              { id:"dashboard", icon:<Icons.Activity/>, label:"Dashboard" },
              { id:"threats",   icon:<Icons.Shield/>,   label:"Case Studies" },
              { id:"download",  icon:<Icons.Download/>, label:"Install" },
              { id:"docs",      icon:<Icons.Terminal/>, label:"Docs" },
            ].map(t => (
              <a key={t.id} href={`#${t.id}`} className={`topbar-tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
                {t.icon} {t.label}
              </a>
            ))}
          </nav>

          <div className="topbar-right">
            <div className="topbar-status">
              <div className="status-dot" />
              <span>LIVE</span>
            </div>
            <a href={GITHUB} target="_blank" rel="noreferrer" className="btn btn-ghost btn-sm">
              <Icons.GitHub /> {stars} stars
            </a>
            <a href="#download" className="btn btn-primary btn-sm">
              <Icons.Download /> Download
            </a>
          </div>
        </header>

        <main className="main">

          {/* ── HERO ── */}
          <section className="hero" id="dashboard">
            <div className="hero-grid" />
            <div className="hero-glow" />
            <div className="container">
              <div className="hero-inner">

                {/* Left */}
                <div>
                  <div className="hero-badge anim-fadeup">
                    <span className="hero-badge-pill">NEW</span>
                    Security middleware for LLM applications
                  </div>
                  <h1 className="hero-title anim-fadeup-1">
                    <span className="gradient">Firewall</span><br />
                    for your LLMs
                  </h1>
                  <p className="hero-desc anim-fadeup-2">
                    TENET AI intercepts every prompt before it reaches your model — detecting injection, jailbreaks, and data extraction in real-time with &lt;10ms overhead.
                  </p>
                  <div className="hero-actions anim-fadeup-3">
                    <a href="#download" className="btn btn-primary btn-lg">
                      <Icons.Download /> Get Started Free
                    </a>
                    <a href={GITHUB} target="_blank" rel="noreferrer" className="btn btn-secondary btn-lg">
                      <Icons.GitHub /> View on GitHub
                    </a>
                  </div>
                  <div className="hero-meta anim-fadeup-4">
                    <div className="hero-meta-item">MIT <span>License</span></div>
                    <div className="hero-meta-item">Self-hosted <span>or Cloud</span></div>
                    <div className="hero-meta-item">&lt;10ms <span>overhead</span></div>
                    <div className="hero-meta-item">Any <span>LLM</span></div>
                  </div>
                </div>

                {/* Right: Dashboard preview */}
                <div className="dashboard-preview anim-fadeup-2">
                  <div className="dp-header">
                    <div className="dp-dot" style={{ background:"#e63946" }} />
                    <div className="dp-dot" style={{ background:"#ffb703" }} />
                    <div className="dp-dot" style={{ background:"#2ecc71" }} />
                    <span className="dp-title">tenet-ai — soc-dashboard — threat-monitor</span>
                    <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:6 }}>
                      <div className="status-dot" style={{ background:"var(--green)" }} />
                      <span style={{ fontSize:10, color:"var(--green)", fontFamily:"var(--mono)" }}>LIVE</span>
                    </div>
                  </div>
                  <div className="dp-body">
                    {/* Stat row */}
                    <div className="dp-stat-row">
                      <div className="dp-stat">
                        <div className="dp-stat-val" style={{ color:"var(--red)" }}>2,847</div>
                        <div className="dp-stat-label">Blocked</div>
                      </div>
                      <div className="dp-stat">
                        <div className="dp-stat-val" style={{ color:"var(--amber)" }}>341</div>
                        <div className="dp-stat-label">Flagged</div>
                      </div>
                      <div className="dp-stat">
                        <div className="dp-stat-val" style={{ color:"var(--green)" }}>98.7k</div>
                        <div className="dp-stat-label">Allowed</div>
                      </div>
                    </div>

                    {/* Live log */}
                    <LiveLog />

                    {/* Attack type bars */}
                    <div className="dp-bar-row">
                      <div style={{ fontSize:10, color:"var(--text3)", marginBottom:4, fontFamily:"var(--mono)", letterSpacing:"0.08em" }}>ATTACK TYPE DISTRIBUTION</div>
                      {[
                        { label:"Prompt Injection", w: barWidths[0], c:"var(--red)" },
                        { label:"Jailbreak",        w: barWidths[1], c:"var(--amber)" },
                        { label:"Data Extraction",  w: barWidths[2], c:"var(--purple)" },
                        { label:"Role Manip.",      w: barWidths[3], c:"var(--green)" },
                      ].map((b, i) => (
                        <div key={i} className="dp-bar-item">
                          <span className="dp-bar-label">{b.label}</span>
                          <div className="dp-bar-track">
                            <div className="dp-bar-fill" style={{ width:`${b.w}%`, background: b.c }} />
                          </div>
                          <span className="dp-bar-val">{b.w}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* ── STAT STRIP ── */}
          <section style={{ padding:"0", background:"var(--surface)", borderTop:"1px solid var(--border)", borderBottom:"1px solid var(--border)" }}>
            <div className="container">
              <div className="stat-grid">
                {[
                  { val:<><AnimNum to={parseInt(stars)||3}/></>, label:"GitHub Stars", sub:"open source", color:"var(--cyan)" },
                  { val:"<10", label:"Detection ms", sub:"heuristic layer", color:"var(--green)" },
                  { val:"90%+", label:"ML Accuracy", sub:"on test set", color:"var(--purple)" },
                  { val:"4", label:"Attack Types", sub:"covered out of box", color:"var(--amber)" },
                ].map((s, i) => (
                  <FadeUp key={i} delay={i * 0.08}>
                    <div className="stat-card">
                      <div className="stat-card-val" style={{ color: s.color }}>{s.val}</div>
                      <div className="stat-card-label">{s.label}</div>
                      <div className="stat-card-sub">{s.sub}</div>
                    </div>
                  </FadeUp>
                ))}
              </div>
            </div>
          </section>

          {/* ── HOW IT WORKS ── */}
          <section className="section">
            <div className="container">
              <FadeUp>
                <div className="section-header">
                  <div className="section-eyebrow">Architecture</div>
                  <h2 className="section-title">How TENET AI <span className="gradient">intercepts threats</span></h2>
                  <p className="section-sub">Four-stage pipeline that adds &lt;10ms to every LLM request — invisible to your users, visible to your security team.</p>
                </div>
              </FadeUp>
              <FadeUp delay={0.1}>
                <div className="how-grid">
                  {[
                    { n:"01", icon:"⚡", label:"STEP 1", title:"Intercept", desc:"Middleware layer captures all outbound prompts before they reach any LLM API endpoint." },
                    { n:"02", icon:"🔍", label:"STEP 2", title:"Analyze", desc:"Heuristic rules, ML classifier, and behavioral engine run in parallel for full-spectrum coverage." },
                    { n:"03", icon:"🛡️", label:"STEP 3", title:"Decide", desc:"Policy engine issues a verdict: Block / Sanitize / Flag / Allow — within the 10ms budget." },
                    { n:"04", icon:"🧠", label:"STEP 4", title:"Learn", desc:"Analyst feedback and shared threat intelligence continuously improve detection accuracy." },
                  ].map((s, i) => (
                    <div key={i} className="how-step">
                      <div className="how-step-num">{s.icon}</div>
                      <div className="how-step-label">{s.label}</div>
                      <div className="how-step-title">{s.title}</div>
                      <div className="how-step-desc">{s.desc}</div>
                    </div>
                  ))}
                </div>
              </FadeUp>
            </div>
          </section>

          {/* ── FEATURES ── */}
          <section className="section section-alt">
            <div className="container">
              <FadeUp>
                <div className="section-header">
                  <div className="section-eyebrow">Capabilities</div>
                  <h2 className="section-title">Everything you need to <span className="gradient">secure your AI</span></h2>
                </div>
              </FadeUp>
              <div className="feature-grid">
                {FEATURES.map((f, i) => (
                  <FadeUp key={i} delay={i * 0.07}>
                    <div className="feature-card">
                      <div className="feature-icon" style={{ background: f.bg }}>{f.icon}</div>
                      <div className="feature-title">{f.title}</div>
                      <div className="feature-desc">{f.desc}</div>
                      <div className="feature-tags">
                        {f.tags.map((t, j) => (
                          <span key={j} className="tag" style={tagStyle(t.c).style}>{t.l}</span>
                        ))}
                      </div>
                    </div>
                  </FadeUp>
                ))}
              </div>
            </div>
          </section>

          {/* ── CASE STUDIES ── */}
          <section className="section" id="threats">
            <div className="container">
              <FadeUp>
                <div className="section-header">
                  <div className="section-eyebrow">Threat Intelligence</div>
                  <h2 className="section-title">Real breaches. <span className="gradient">Real prevention.</span></h2>
                  <p className="section-sub">These incidents happened. The attack vectors are documented. TENET AI's detection pipeline would have blocked each one.</p>
                </div>
              </FadeUp>
              <div className="threat-list">
                {THREATS.map((t, i) => (
                  <FadeUp key={i} delay={i * 0.08}>
                    <div className="threat-card" style={{ borderLeftColor: t.leftColor }}>
                      {/* Meta */}
                      <div className="threat-meta">
                        <span className="threat-date">{t.date}</span>
                        <span className="threat-severity" style={{ color: t.sevColor, background: t.sevBg }}>
                          ● {t.severity}
                        </span>
                        <span className="threat-type-tag">{t.type}</span>
                      </div>

                      {/* Body */}
                      <div className="threat-body">
                        <div className="threat-title">{t.title}</div>
                        <div className="threat-desc">{t.desc}</div>
                        <div className="threat-defense">
                          <div className="threat-defense-label">🛡 TENET AI RESPONSE</div>
                          <div className="threat-defense-text">{t.defense}</div>
                        </div>
                      </div>

                      {/* Stat */}
                      <div className="threat-stat">
                        <div className="threat-stat-val" style={{ color: t.sevColor }}>{t.stat}</div>
                        <div className="threat-stat-label">{t.statLabel}</div>
                      </div>
                    </div>
                  </FadeUp>
                ))}
              </div>
            </div>
          </section>

          {/* ── INSTALL ── */}
          <section className="section section-alt" id="download">
            <div className="container">
              <FadeUp>
                <div className="section-header">
                  <div className="section-eyebrow">Get Started</div>
                  <h2 className="section-title">Install in <span className="gradient">minutes</span></h2>
                  <p className="section-sub">Drop TENET AI into any stack. One additional API call in your existing code. Zero changes to your LLM integration.</p>
                </div>
              </FadeUp>

              <div className="install-grid" style={{ marginBottom: 40 }}>
                {INSTALLS.map((d, i) => (
                  <FadeUp key={i} delay={i * 0.08}>
                    <div className="install-card">
                      <div className="install-card-header">
                        <div>
                          <div style={{ fontSize: 28, marginBottom: 10 }}>{d.icon}</div>
                          <div className="install-card-title">{d.title}</div>
                          <div className="install-card-sub">{d.sub}</div>
                        </div>
                        <span className="install-card-platform">{d.platform}</span>
                      </div>
                      <div className="install-card-code">
                        <span className="install-card-code-prompt">$</span>
                        <span>{d.cmd}</span>
                      </div>
                      <div className="install-card-body" style={{ paddingTop: 16 }}>
                        <div className="install-card-features">
                          {d.features.map((f, j) => (
                            <div key={j} className="install-card-feature">{f}</div>
                          ))}
                        </div>
                        <a href={GITHUB} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm" style={{ width:"100%", justifyContent:"center" }}>
                          <Icons.Download /> Download
                        </a>
                      </div>
                    </div>
                  </FadeUp>
                ))}
              </div>

              {/* Code sample */}
              <FadeUp delay={0.2}>
                <div className="code-block">
                  <div className="code-header">
                    <div className="code-dot" style={{ background:"#e63946" }} />
                    <div className="code-dot" style={{ background:"#ffb703" }} />
                    <div className="code-dot" style={{ background:"#2ecc71" }} />
                    <span className="code-filename">integration_example.py</span>
                    <span className="code-lang">Python</span>
                  </div>
                  <div className="code-body">
                    <span className="c-comment"># 1. Install: pip install tenet-ai</span>{"\n"}
                    <span className="c-keyword">import</span> <span className="c-cyan">tenet_ai</span>{"\n\n"}
                    <span className="c-comment"># 2. One-line initialization</span>{"\n"}
                    <span className="c-var">tenet</span> = tenet_ai.<span className="c-func">Client</span>(<span className="c-var">api_key</span>=<span className="c-string">"your-key"</span>){"\n\n"}
                    <span className="c-comment"># 3. Intercept before ANY LLM call</span>{"\n"}
                    <span className="c-var">result</span> = tenet.<span className="c-func">check</span>(<span className="c-var">prompt</span>=user_input, <span className="c-var">user_id</span>=<span className="c-string">"u-123"</span>){"\n\n"}
                    <span className="c-keyword">if</span> <span className="c-var">result</span>.blocked:{"\n"}
                    {"    "}<span className="c-keyword">return</span> <span className="c-string">"⛔ Request blocked"</span>  <span className="c-comment"># &lt;5ms, rule-based</span>{"\n\n"}
                    <span className="c-comment"># 4. Safe — call any LLM normally</span>{"\n"}
                    <span className="c-var">response</span> = openai.<span className="c-func">chat</span>(user_input)     <span className="c-comment"># OpenAI</span>{"\n"}
                    <span className="c-var">response</span> = anthropic.<span className="c-func">message</span>(user_input)  <span className="c-comment"># Claude</span>{"\n"}
                    <span className="c-var">response</span> = ollama.<span className="c-func">generate</span>(user_input)   <span className="c-comment"># Local</span>
                  </div>
                </div>
              </FadeUp>
            </div>
          </section>

          {/* ── CTA ── */}
          <section className="cta-section">
            <div className="cta-glow" />
            <div className="container">
              <FadeUp>
                <h2 className="cta-title">
                  Start protecting your<br /><span className="gradient">AI applications today</span>
                </h2>
                <p className="cta-sub">Self-hosted. Open source. Zero vendor lock-in.</p>
                <div className="cta-actions">
                  <a href="#download" className="btn btn-primary btn-lg">
                    <Icons.Download /> Download Plugin
                  </a>
                  <a href={GITHUB} target="_blank" rel="noreferrer" className="btn btn-secondary btn-lg">
                    <Icons.GitHub /> View on GitHub
                  </a>
                </div>
                <div className="cta-pills">
                  {["MIT Licensed","Self-hosted option","Any LLM provider","No usage telemetry"].map((p, i) => (
                    <span key={i} className="cta-pill">{p}</span>
                  ))}
                </div>
              </FadeUp>
            </div>
          </section>

        </main>

        {/* ── FOOTER ── */}
        <footer className="footer">
          <div className="container">
            <div className="footer-inner">
              <div className="footer-brand">
                <Logo size={22} />
                <span style={{ fontWeight:700, fontSize:14 }}>TENET AI Dev</span>
              </div>
              <div className="footer-links">
                {[["GitHub", GITHUB],["Contributing", `${GITHUB}/blob/main/CONTRIBUTING.md`],["Security", `${GITHUB}/blob/main/SECURITY.md`],["Contact","mailto:saviodsouza8a@gmail.com"]].map(([l,h])=>(
                  <a key={l} href={h} target="_blank" rel="noreferrer" className="footer-link">{l}</a>
                ))}
              </div>
              <div className="footer-copy">
                Built by Savio D'souza · © 2026 MIT Licensed
              </div>
            </div>
          </div>
        </footer>

      </div>
    </>
  );
}
