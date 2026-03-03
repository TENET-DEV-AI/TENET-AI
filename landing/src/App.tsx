import { useState, useEffect, useRef } from "react";

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@300;400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080a0e;--surface:#0f1116;--surface2:#14171f;--surface3:#1a1d28;
  --border:#1e2130;--border2:#252a3a;
  --cyan:#00d4ff;--cyan-dim:rgba(0,212,255,0.08);--cyan-glow:rgba(0,212,255,0.2);
  --red:#e63946;--red-dim:rgba(230,57,70,0.1);
  --amber:#ffb703;--amber-dim:rgba(255,183,3,0.1);
  --green:#2dd4bf;--green-dim:rgba(45,212,191,0.1);
  --purple:#a78bfa;--purple-dim:rgba(167,139,250,0.1);
  --text:#dde1ef;--text2:#8890a8;--text3:#484f66;
  --font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace;
  --radius:10px;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--font);-webkit-font-smoothing:antialiased;overflow-x:hidden}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:var(--cyan)}

.page{display:flex;flex-direction:column;min-height:100vh}

/* TOPBAR */
.topbar{position:fixed;top:0;left:0;right:0;z-index:100;height:60px;background:rgba(8,10,14,0.9);border-bottom:1px solid var(--border);backdrop-filter:blur(20px);display:flex;align-items:center;padding:0 32px;gap:0}
.brand{display:flex;align-items:center;gap:12px;text-decoration:none;min-width:220px}
.brand-logo{display:flex;align-items:center;justify-content:center}
.brand-name{font-weight:800;font-size:16px;color:var(--cyan);letter-spacing:-0.01em}
.brand-badge{font-size:9px;background:var(--cyan-dim);color:var(--cyan);border:1px solid rgba(0,212,255,0.2);border-radius:4px;padding:2px 6px;font-family:var(--mono);margin-left:2px}
.nav{display:flex;align-items:center;height:100%;gap:0;margin-left:16px;flex:1}
.nav-link{display:flex;align-items:center;gap:6px;height:100%;padding:0 16px;font-size:12.5px;font-weight:500;color:var(--text3);text-decoration:none;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.15s;white-space:nowrap}
.nav-link:hover{color:var(--text2);background:rgba(255,255,255,0.02)}
.nav-link.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.topbar-right{display:flex;align-items:center;gap:10px;margin-left:auto}
.live-badge{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--green);font-family:var(--mono);background:var(--green-dim);border:1px solid rgba(45,212,191,0.2);padding:4px 10px;border-radius:20px}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
.btn{display:inline-flex;align-items:center;gap:7px;border:none;cursor:pointer;font-family:var(--font);font-weight:600;border-radius:7px;text-decoration:none;transition:all 0.18s;white-space:nowrap;letter-spacing:-0.01em}
.btn-sm{font-size:12px;padding:7px 14px}
.btn-md{font-size:13px;padding:10px 20px}
.btn-lg{font-size:14px;padding:13px 26px}
.btn-xl{font-size:15px;padding:15px 32px}
.btn-primary{background:var(--cyan);color:#080a0e}
.btn-primary:hover{background:#1adeff;box-shadow:0 0 28px var(--cyan-glow);transform:translateY(-1px)}
.btn-outline{background:transparent;color:var(--text);border:1px solid var(--border2)}
.btn-outline:hover{border-color:var(--cyan);color:var(--cyan)}
.btn-ghost{background:transparent;color:var(--text2);border:1px solid var(--border)}
.btn-ghost:hover{color:var(--cyan);border-color:rgba(0,212,255,0.3)}

.main{margin-top:60px;flex:1}
.container{max-width:1180px;margin:0 auto;padding:0 28px}
.section{padding:80px 0}
.section-alt{background:var(--surface)}
.eyebrow{display:flex;align-items:center;gap:8px;font-size:10.5px;font-family:var(--mono);color:var(--cyan);letter-spacing:0.14em;text-transform:uppercase;margin-bottom:14px}
.eyebrow::before{content:'';width:18px;height:1px;background:var(--cyan);flex-shrink:0}
.section-title{font-size:32px;font-weight:800;letter-spacing:-0.025em;line-height:1.15;margin-bottom:12px}
.section-sub{font-size:14px;color:var(--text2);max-width:540px;line-height:1.75}
.grad{background:linear-gradient(110deg,#fff 0%,var(--cyan) 50%,#0088aa 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}

/* HERO */
.hero{padding:100px 0 80px;position:relative;overflow:hidden;background:var(--bg)}
.hero-grid{position:absolute;inset:0;background-image:linear-gradient(rgba(0,212,255,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.04) 1px,transparent 1px);background-size:52px 52px;pointer-events:none}
.hero-glow1{position:absolute;top:-160px;left:50%;transform:translateX(-50%);width:900px;height:500px;background:radial-gradient(ellipse,rgba(0,212,255,0.055) 0%,transparent 65%);pointer-events:none}
.hero-glow2{position:absolute;bottom:-100px;right:-100px;width:500px;height:500px;background:radial-gradient(ellipse,rgba(167,139,250,0.04) 0%,transparent 70%);pointer-events:none}
.hero-inner{position:relative;display:grid;grid-template-columns:1fr 1fr;gap:72px;align-items:center}
.hero-kicker{display:inline-flex;align-items:center;gap:8px;background:var(--surface2);border:1px solid var(--border2);border-radius:24px;padding:6px 16px 6px 10px;font-size:11.5px;color:var(--text2);margin-bottom:28px}
.hero-kicker-pill{background:var(--cyan);color:#080a0e;font-size:9px;font-weight:700;padding:2px 8px;border-radius:10px;letter-spacing:0.06em}
.hero-title{font-size:54px;font-weight:900;letter-spacing:-0.035em;line-height:1.05;margin-bottom:22px}
.hero-desc{font-size:15px;color:var(--text2);line-height:1.8;margin-bottom:36px;max-width:460px}
.hero-actions{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:44px}
.hero-pills{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.hero-pill{display:flex;align-items:center;gap:6px;font-size:11.5px;color:var(--text3);font-family:var(--mono)}
.hero-pill-dot{width:5px;height:5px;border-radius:50%;background:var(--cyan);flex-shrink:0}

/* PREVIEW CARD */
.preview{background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden;box-shadow:0 40px 100px rgba(0,0,0,0.6),0 0 0 1px rgba(0,212,255,0.04)}
.preview-bar{background:var(--surface2);border-bottom:1px solid var(--border);padding:11px 16px;display:flex;align-items:center;gap:7px}
.preview-dot{width:11px;height:11px;border-radius:50%}
.preview-title{font-size:11px;color:var(--text3);margin-left:8px;font-family:var(--mono);flex:1}
.preview-live{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--green);font-family:var(--mono)}
.preview-body{padding:14px;display:flex;flex-direction:column;gap:10px}
.p-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.p-stat{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.p-stat-v{font-size:24px;font-weight:700;font-family:var(--mono);line-height:1;margin-bottom:4px}
.p-stat-l{font-size:9.5px;color:var(--text3);text-transform:uppercase;letter-spacing:0.1em}
.p-log{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-family:var(--mono);font-size:10.5px;display:flex;flex-direction:column;gap:5px;min-height:88px}
.p-log-row{display:flex;gap:8px;align-items:center;opacity:0;animation:fadeRow 0.3s ease forwards}
.p-log-time{color:var(--text3);min-width:58px;font-size:10px}
.p-log-tag{font-size:8.5px;font-weight:700;padding:1px 6px;border-radius:3px;min-width:52px;text-align:center;letter-spacing:0.04em}
.p-log-msg{color:#4e5568;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:10px}
.p-bars{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 14px;display:flex;flex-direction:column;gap:7px}
.p-bar-head{font-size:9px;color:var(--text3);font-family:var(--mono);letter-spacing:0.1em;text-transform:uppercase;margin-bottom:2px}
.p-bar-row{display:flex;align-items:center;gap:8px}
.p-bar-lbl{font-size:9.5px;color:var(--text3);min-width:96px;font-family:var(--mono)}
.p-bar-track{flex:1;height:3px;background:var(--border);border-radius:2px;overflow:hidden}
.p-bar-fill{height:100%;border-radius:2px;transition:width 1.8s cubic-bezier(0.4,0,0.2,1)}
.p-bar-val{font-size:9.5px;color:var(--text2);font-family:var(--mono);min-width:30px;text-align:right}

/* STATS STRIP */
.stats-strip{background:var(--surface);border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:0}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);divide-x:1px solid var(--border)}
.stat-block{padding:28px 32px;border-right:1px solid var(--border)}
.stat-block:last-child{border-right:none}
.stat-val{font-size:38px;font-weight:800;font-family:var(--mono);letter-spacing:-0.03em;line-height:1;margin-bottom:6px}
.stat-lbl{font-size:11.5px;color:var(--text3);text-transform:uppercase;letter-spacing:0.09em;font-weight:500}
.stat-sub{font-size:10.5px;color:var(--text3);margin-top:3px;font-family:var(--mono)}

/* HOW */
.how-grid{display:grid;grid-template-columns:repeat(4,1fr);position:relative;gap:0}
.how-line{position:absolute;top:27px;left:calc(12.5% + 13px);right:calc(12.5% + 13px);height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent)}
.how-step{padding:0 20px;text-align:center}
.how-num{width:54px;height:54px;border-radius:50%;background:var(--surface);border:1px solid var(--border2);display:flex;align-items:center;justify-content:center;font-size:20px;margin:0 auto 20px;position:relative;z-index:1;transition:all 0.22s}
.how-step:hover .how-num{border-color:var(--cyan);box-shadow:0 0 24px var(--cyan-glow);background:var(--cyan-dim)}
.how-tag{font-size:9.5px;font-family:var(--mono);color:var(--cyan);letter-spacing:0.14em;margin-bottom:8px}
.how-title{font-size:14px;font-weight:700;margin-bottom:8px}
.how-desc{font-size:12px;color:var(--text2);line-height:1.65}

/* FEATURES */
.feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.feat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:26px;transition:all 0.22s;position:relative;overflow:hidden;cursor:default}
.feat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);opacity:0;transition:opacity 0.22s}
.feat-card:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:0 16px 48px rgba(0,0,0,0.35)}
.feat-card:hover::before{opacity:1}
.feat-icon{width:42px;height:42px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:16px}
.feat-title{font-size:14.5px;font-weight:700;margin-bottom:8px}
.feat-desc{font-size:12.5px;color:var(--text2);line-height:1.7}
.feat-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.tag{font-size:10px;font-family:var(--mono);padding:3px 9px;border-radius:4px;border:1px solid transparent}

/* THREATS */
.threat-list{display:flex;flex-direction:column;gap:14px}
.threat{background:var(--surface);border:1px solid var(--border);border-left:3px solid;border-radius:var(--radius);padding:22px;display:grid;grid-template-columns:160px 1fr 90px;gap:20px;align-items:start;transition:all 0.2s;cursor:default}
.threat:hover{background:var(--surface2);transform:translateX(4px)}
.threat-meta{display:flex;flex-direction:column;gap:6px}
.threat-date{font-size:10px;font-family:var(--mono);color:var(--text3)}
.threat-sev{font-size:10.5px;font-weight:700;padding:3px 9px;border-radius:4px;display:inline-flex;align-items:center;gap:4px;width:fit-content}
.threat-type{font-size:9.5px;font-family:var(--mono);color:var(--text3);background:var(--surface3);padding:2px 7px;border-radius:3px;width:fit-content}
.threat-title{font-size:14px;font-weight:700;margin-bottom:6px}
.threat-desc{font-size:12px;color:var(--text2);line-height:1.65;margin-bottom:10px}
.threat-resp{background:rgba(0,212,255,0.04);border:1px solid rgba(0,212,255,0.12);border-radius:6px;padding:10px 13px}
.threat-resp-lbl{font-size:9px;font-family:var(--mono);color:var(--cyan);letter-spacing:0.12em;margin-bottom:4px;font-weight:700}
.threat-resp-text{font-size:11.5px;color:var(--text2);line-height:1.6}
.threat-num{text-align:right}
.threat-num-val{font-size:22px;font-weight:800;font-family:var(--mono);line-height:1}
.threat-num-lbl{font-size:9.5px;color:var(--text3);margin-top:3px}

/* INSTALL */
.install-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
.install-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;transition:all 0.22s}
.install-card:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:0 20px 56px rgba(0,0,0,0.35)}
.install-head{padding:20px 20px 0;display:flex;align-items:flex-start;justify-content:space-between}
.install-icon{font-size:30px;margin-bottom:10px}
.install-plat{font-size:9.5px;font-family:var(--mono);color:var(--text3);background:var(--surface3);padding:2px 8px;border-radius:4px}
.install-title{font-size:15px;font-weight:700;margin-bottom:4px}
.install-sub{font-size:12px;color:var(--text2);margin-bottom:14px}
.install-cmd{background:var(--bg);border-top:1px solid var(--border);padding:12px 20px;font-family:var(--mono);font-size:12px;color:var(--cyan);display:flex;align-items:center;gap:8px}
.install-prompt{color:var(--text3)}
.install-body{padding:16px 20px 20px}
.install-features{display:flex;flex-direction:column;gap:5px;margin-bottom:14px}
.install-feat{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--text2)}
.install-feat::before{content:'';width:4px;height:4px;border-radius:50%;background:var(--cyan);flex-shrink:0}

/* CODE */
.code-block{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.code-head{background:var(--surface);border-bottom:1px solid var(--border);padding:11px 18px;display:flex;align-items:center;gap:8px}
.code-dot2{width:11px;height:11px;border-radius:50%;flex-shrink:0}
.code-file{font-size:12px;color:var(--text3);font-family:var(--mono);margin-left:8px}
.code-lang-badge{font-size:9.5px;font-family:var(--mono);color:var(--text3);background:var(--surface3);padding:2px 8px;border-radius:3px;margin-left:auto}
.code-body{padding:22px 26px;font-family:var(--mono);font-size:12.5px;line-height:2;overflow-x:auto}
.cc{color:#3d4560}.ck{color:#c792ea}.cs{color:#c3e88d}.cf{color:#82aaff}.cy{color:var(--cyan)}.cd{color:#3d4560}

/* CTA */
.cta{padding:96px 0;text-align:center;position:relative;overflow:hidden}
.cta-glow{position:absolute;inset:0;background:radial-gradient(ellipse at center,rgba(0,212,255,0.055) 0%,transparent 65%);pointer-events:none}
.cta-title{font-size:44px;font-weight:900;letter-spacing:-0.03em;margin-bottom:16px}
.cta-sub{font-size:15px;color:var(--text2);margin-bottom:40px}
.cta-btns{display:flex;gap:14px;justify-content:center;flex-wrap:wrap;margin-bottom:36px}
.cta-chips{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
.cta-chip{font-size:11.5px;color:var(--text3);background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:5px 15px;display:flex;align-items:center;gap:6px}
.cta-chip::before{content:'✓';color:var(--cyan);font-size:10px}

/* FOOTER */
.footer{background:var(--surface);border-top:1px solid var(--border);padding:36px 0}
.footer-inner{display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap}
.footer-brand{display:flex;align-items:center;gap:10px}
.footer-name{font-weight:700;font-size:14px;color:var(--cyan)}
.footer-links{display:flex;gap:24px}
.footer-link{font-size:12.5px;color:var(--text3);text-decoration:none;transition:color 0.15s}
.footer-link:hover{color:var(--cyan)}
.footer-copy{font-size:11px;color:var(--text3);font-family:var(--mono)}

@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(0.8)}}
@keyframes fadeRow{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:translateX(0)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(22px)}to{opacity:1;transform:translateY(0)}}
.au{animation:fadeUp 0.6s ease both}
.au1{animation:fadeUp 0.6s 0.1s ease both}
.au2{animation:fadeUp 0.6s 0.2s ease both}
.au3{animation:fadeUp 0.6s 0.3s ease both}
.au4{animation:fadeUp 0.6s 0.4s ease both}

@media(max-width:1024px){.hero-inner{grid-template-columns:1fr}.preview{display:none}.feat-grid{grid-template-columns:1fr 1fr}.how-grid{grid-template-columns:1fr 1fr;gap:28px}.how-line{display:none}.stats-grid{grid-template-columns:1fr 1fr}}
@media(max-width:768px){.hero-title{font-size:38px}.install-grid{grid-template-columns:1fr}.feat-grid{grid-template-columns:1fr}.threat{grid-template-columns:1fr;gap:12px}.threat-num{text-align:left}.stats-grid{grid-template-columns:1fr 1fr}}
@media(max-width:480px){.stats-grid{grid-template-columns:1fr}.cta-title{font-size:30px}}
`;

// ── LOGO (matches the real cubic TENET AI Dev logo style)
const TenetLogo = ({ size = 32 }) => (
  <svg width={size} height={size} viewBox="0 0 80 80" fill="none">
    <defs>
      <linearGradient id="tg1" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stopColor="#00d4ff"/>
        <stop offset="100%" stopColor="#0099cc"/>
      </linearGradient>
      <linearGradient id="tg2" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stopColor="#00aadd"/>
        <stop offset="100%" stopColor="#006699"/>
      </linearGradient>
    </defs>
    {/* Outer cube outline */}
    <path d="M40 6 L72 22 L72 58 L40 74 L8 58 L8 22 Z" fill="none" stroke="url(#tg1)" strokeWidth="1.5" opacity="0.6"/>
    {/* Top face */}
    <path d="M40 6 L72 22 L40 38 L8 22 Z" fill="rgba(0,212,255,0.12)" stroke="url(#tg1)" strokeWidth="1.5"/>
    {/* Right face */}
    <path d="M72 22 L72 58 L40 74 L40 38 Z" fill="rgba(0,153,204,0.08)" stroke="url(#tg2)" strokeWidth="1.5"/>
    {/* Left face */}
    <path d="M8 22 L40 38 L40 74 L8 58 Z" fill="rgba(0,100,150,0.06)" stroke="url(#tg2)" strokeWidth="1.2"/>
    {/* Inner geometric pattern - top */}
    <path d="M40 14 L64 26 L40 38 L16 26 Z" fill="none" stroke="rgba(0,212,255,0.35)" strokeWidth="1"/>
    {/* Inner lines */}
    <line x1="40" y1="6" x2="40" y2="74" stroke="url(#tg1)" strokeWidth="0.8" opacity="0.4"/>
    <line x1="8" y1="22" x2="72" y2="58" stroke="url(#tg1)" strokeWidth="0.8" opacity="0.3"/>
    <line x1="72" y1="22" x2="8" y2="58" stroke="url(#tg1)" strokeWidth="0.8" opacity="0.3"/>
    {/* Inner cube detail */}
    <path d="M40 22 L56 30 L56 46 L40 54 L24 46 L24 30 Z" fill="none" stroke="rgba(0,212,255,0.5)" strokeWidth="1.2"/>
    <path d="M40 22 L56 30 L40 38 L24 30 Z" fill="rgba(0,212,255,0.1)" stroke="rgba(0,212,255,0.5)" strokeWidth="1"/>
    {/* Center dot */}
    <circle cx="40" cy="38" r="3.5" fill="#00d4ff" opacity="0.9"/>
    {/* Corner dots */}
    {[[40,6],[72,22],[72,58],[40,74],[8,58],[8,22]].map(([cx,cy],i)=>(
      <circle key={i} cx={cx} cy={cy} r="2.5" fill="#00d4ff" opacity="0.65"/>
    ))}
    {/* Mid dots */}
    {[[56,30],[56,46],[40,54],[24,46],[24,30],[40,22]].map(([cx,cy],i)=>(
      <circle key={i} cx={cx} cy={cy} r="1.5" fill="#00d4ff" opacity="0.4"/>
    ))}
  </svg>
);

const Icons = {
  Shield:()=><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Zap:()=><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>,
  Download:()=><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>,
  GitHub:()=><svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>,
  Terminal:()=><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>,
  Activity:()=><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  Eye:()=><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
};

const LOGS = [
  {tag:"BLOCKED",tc:"#e63946",tb:"rgba(230,57,70,0.15)",msg:"prompt_injection · ignore_instructions",src:"api.prod"},
  {tag:"ALLOWED",tc:"#2dd4bf",tb:"rgba(45,212,191,0.12)",msg:"normal_query · risk_score:0.02",src:"chat.app"},
  {tag:"BLOCKED",tc:"#e63946",tb:"rgba(230,57,70,0.15)",msg:"jailbreak · DAN_mode variant",src:"agt.01"},
  {tag:"FLAGGED",tc:"#ffb703",tb:"rgba(255,183,3,0.12)",msg:"data_extraction · system_prompt probe",src:"api.dev"},
  {tag:"BLOCKED",tc:"#e63946",tb:"rgba(230,57,70,0.15)",msg:"role_manipulation · persona_override",src:"embed.01"},
  {tag:"ALLOWED",tc:"#2dd4bf",tb:"rgba(45,212,191,0.12)",msg:"normal_query · risk_score:0.01",src:"chat.app"},
];

function LiveLog() {
  const [lines, setLines] = useState(LOGS.slice(0,4));
  const [idx, setIdx] = useState(4);
  useEffect(()=>{
    const t = setInterval(()=>{
      setLines(p=>[...p.slice(-3), LOGS[idx%LOGS.length]]);
      setIdx(i=>i+1);
    },2400);
    return ()=>clearInterval(t);
  },[idx]);
  const now = new Date();
  const fmt = off => { const d=new Date(now-off*1000); return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`; };
  return (
    <div className="p-log">
      {lines.map((l,i)=>(
        <div key={`${idx}-${i}`} className="p-log-row" style={{animationDelay:`${i===lines.length-1?0:0}s`,opacity:0.45+i*0.18}}>
          <span className="p-log-time">{fmt((lines.length-1-i)*3)}</span>
          <span className="p-log-tag" style={{color:l.tc,background:l.tb}}>{l.tag}</span>
          <span className="p-log-msg">{l.msg}</span>
          <span style={{color:'#2e3348',fontSize:9.5,fontFamily:'var(--mono)'}}>{l.src}</span>
        </div>
      ))}
    </div>
  );
}

function AnimNum({to,dur=1400}){
  const [v,setV]=useState(0); const ref=useRef(); const started=useRef(false);
  useEffect(()=>{
    const obs=new IntersectionObserver(([e])=>{
      if(e.isIntersecting&&!started.current){
        started.current=true;
        const steps=50;let s=0;
        const t=setInterval(()=>{ s++;setV(Math.round(to*Math.min(s/steps,1)));if(s>=steps)clearInterval(t); },dur/steps);
      }
    },{threshold:0.4});
    if(ref.current)obs.observe(ref.current);
    return()=>obs.disconnect();
  },[to]);
  return <span ref={ref}>{v.toLocaleString()}</span>;
}

function FadeUp({children,delay=0,style={}}){
  const ref=useRef();const[vis,setVis]=useState(false);
  useEffect(()=>{
    const obs=new IntersectionObserver(([e])=>{if(e.isIntersecting){setVis(true);obs.disconnect();}},{threshold:0.08});
    if(ref.current)obs.observe(ref.current);
    return()=>obs.disconnect();
  },[]);
  return(
    <div ref={ref} style={{opacity:vis?1:0,transform:vis?'none':'translateY(20px)',transition:`opacity 0.55s ${delay}s ease,transform 0.55s ${delay}s ease`,...style}}>
      {children}
    </div>
  );
}

const THREATS = [
  {date:"FEB 2026",type:"JAILBREAK",title:"Mexican Government AI Breach",sev:"CRITICAL",sc:"#e63946",sb:"rgba(230,57,70,0.12)",stat:"195M",sl:"Records",desc:"Attacker chained jailbreak prompts through Claude to exfiltrate government records across 47 federal agencies. Role-play injection bypassed standard content filters over multiple sessions.",resp:"Detected 'act as elite hacker' + role-play chain. Blocked at 4ms. Session fingerprinted and terminated.",lc:"#e63946"},
  {date:"JAN 2026",type:"PROMPT INJECTION",title:"Fortune 500 Chatbot Compromise",sev:"HIGH",sc:"#ffb703",sb:"rgba(255,183,3,0.12)",stat:"$4.2M",sl:"Loss",desc:"Customer chatbot exploited via iterative prompt injection exposing internal pricing models and PII across 47 payload variations.",resp:"Detected structural similarity across 47 attempts. Auto-blocked after threshold. Risk score elevated progressively.",lc:"#ffb703"},
  {date:"DEC 2025",type:"JAILBREAK",title:"Healthcare Enterprise Breach",sev:"HIGH",sc:"#ffb703",sb:"rgba(255,183,3,0.12)",stat:"HIPAA",sl:"Violation",desc:"Internal clinical AI jailbroken via DAN mode granting unrestricted access to patient record queries across a hospital network.",resp:"Blocked jailbreak on attempt #1. Behavioral fingerprint added to shared threat feed in real-time.",lc:"#a78bfa"},
  {date:"NOV 2025",type:"IP EXTRACTION",title:"Corporate Algorithm Exfiltration",sev:"MEDIUM",sc:"#2dd4bf",sb:"rgba(45,212,191,0.12)",stat:"12",sl:"Sessions",desc:"Nation-state actor used 12 sessions of multi-turn context manipulation to gradually extract proprietary encryption algorithms from a coding assistant.",resp:"ML model detected anomaly at session 4. Full 12-session attack chain reconstructed for forensics.",lc:"#2dd4bf"},
];

const FEATURES = [
  {icon:"🔍",bg:"var(--cyan-dim)",title:"Heuristic Detection",desc:"Zero-config pattern matching for known attack signatures — prompt injection, jailbreaks, role manipulation out of the box.",tags:[{l:"<5ms",c:"cyan"},{l:"zero-config",c:"dim"}]},
  {icon:"🧠",bg:"var(--purple-dim)",title:"ML-Based Analysis",desc:"Trained classifier achieving >90% accuracy on adversarial datasets. Continuously improves from analyst feedback.",tags:[{l:">90% accuracy",c:"purple"},{l:"adaptive",c:"dim"}]},
  {icon:"👁",bg:"var(--amber-dim)",title:"Behavioral Analysis",desc:"Cross-session pattern tracking detects coordinated attacks and multi-turn manipulation chains that single-shot models miss.",tags:[{l:"cross-session",c:"amber"},{l:"anomaly detection",c:"dim"}]},
  {icon:"⚡",bg:"var(--green-dim)",title:"Real-Time Policy Engine",desc:"Block, sanitize, flag, or allow — configurable rules execute in under 10ms total overhead with zero LLM integration changes.",tags:[{l:"<10ms",c:"green"},{l:"configurable",c:"dim"}]},
  {icon:"📊",bg:"var(--cyan-dim)",title:"SOC Dashboard",desc:"Live threat feeds, attack timelines, risk score trends, and analyst workflows. Audit-ready for compliance teams.",tags:[{l:"real-time",c:"cyan"},{l:"SOC-ready",c:"dim"}]},
  {icon:"🔌",bg:"var(--purple-dim)",title:"Universal Integration",desc:"LLM-agnostic middleware for OpenAI, Anthropic, Cohere, Ollama, and any local model. One API call in your existing stack.",tags:[{l:"any LLM",c:"purple"},{l:"one API call",c:"dim"}]},
];

const INSTALLS = [
  {icon:"🐍",plat:"Python",title:"Python SDK",sub:"Async-first middleware for Python apps",cmd:"pip install tenet-ai",feats:["FastAPI / Django / Flask","LangChain & LlamaIndex","Full async/await support","Complete type hints"]},
  {icon:"📦",plat:"Node.js",title:"Node.js Package",sub:"TypeScript-native NPM package",cmd:"npm install @tenet-ai/sdk",feats:["Express / Next.js middleware","Cloudflare Workers support","TypeScript out of the box","Edge runtime compatible"]},
  {icon:"🐳",plat:"Docker",title:"Docker Image",sub:"Self-hosted REST API + SOC dashboard",cmd:"docker pull tenetai/core",feats:["One-command deployment","SOC dashboard included","Prometheus + Grafana ready","PostgreSQL + Redis bundled"]},
  {icon:"☁️",plat:"Cloud",title:"Cloud Templates",sub:"Infrastructure-as-code for all major clouds",cmd:"helm install tenet-ai ./chart",feats:["AWS Lambda layer","Azure Functions extension","GCP Cloud Run template","Kubernetes Helm chart"]},
];

const GITHUB = "https://github.com/TENET-DEV-AI/TENET-AI";

export default function App() {
  const [tab,setTab] = useState("home");
  const [stars,setStars] = useState("3");
  const [bars,setBars] = useState([0,0,0,0]);

  useEffect(()=>{
    fetch("https://api.github.com/repos/TENET-DEV-AI/TENET-AI")
      .then(r=>r.json()).then(d=>{if(d.stargazers_count!=null)setStars(d.stargazers_count);}).catch(()=>{});
    setTimeout(()=>setBars([92,7,1,0.4]),700);
  },[]);

  const tagCss = c => ({
    color: c==="cyan"?"var(--cyan)":c==="purple"?"var(--purple)":c==="amber"?"var(--amber)":c==="green"?"var(--green)":"var(--text3)",
    background: c==="cyan"?"var(--cyan-dim)":c==="purple"?"var(--purple-dim)":c==="amber"?"var(--amber-dim)":c==="green"?"var(--green-dim)":"var(--surface3)",
    borderColor: c==="cyan"?"rgba(0,212,255,0.2)":c==="purple"?"rgba(167,139,250,0.2)":c==="amber"?"rgba(255,183,3,0.2)":c==="green"?"rgba(45,212,191,0.2)":"var(--border)",
  });

  return (
    <>
      <style dangerouslySetInnerHTML={{__html:CSS}}/>
      <div className="page">

        {/* TOPBAR */}
        <header className="topbar">
          <a href="#" className="brand">
            <div className="brand-logo"><TenetLogo size={30}/></div>
            <span className="brand-name">TENET AI Dev</span>
            <span className="brand-badge">v0.1</span>
          </a>
          <nav className="nav">
            {[{id:"home",icon:<Icons.Activity/>,l:"Dashboard"},{id:"threats",icon:<Icons.Shield/>,l:"Case Studies"},{id:"download",icon:<Icons.Download/>,l:"Install"},{id:"docs",icon:<Icons.Terminal/>,l:"Docs"}].map(t=>(
              <a key={t.id} href={`#${t.id}`} className={`nav-link ${tab===t.id?"active":""}`} onClick={()=>setTab(t.id)}>
                {t.icon}{t.l}
              </a>
            ))}
          </nav>
          <div className="topbar-right">
            <div className="live-badge"><div className="dot"/>LIVE</div>
            <a href={GITHUB} target="_blank" rel="noreferrer" className="btn btn-ghost btn-sm"><Icons.GitHub/> {stars} stars</a>
            <a href="#download" className="btn btn-primary btn-sm"><Icons.Download/> Download</a>
          </div>
        </header>

        <main className="main">

          {/* HERO */}
          <section className="hero" id="home">
            <div className="hero-grid"/>
            <div className="hero-glow1"/>
            <div className="hero-glow2"/>
            <div className="container">
              <div className="hero-inner">
                <div>
                  <div className="hero-kicker au">
                    <span className="hero-kicker-pill">NEW</span>
                    LLM Security Middleware · Open Source
                  </div>
                  <h1 className="hero-title au1">
                    The <span className="grad">Firewall</span><br/>for your AI
                  </h1>
                  <p className="hero-desc au2">
                    TENET AI sits between your app and any LLM — detecting prompt injection, jailbreaks, and data extraction in real-time with under 10ms overhead.
                  </p>
                  <div className="hero-actions au3">
                    <a href="#download" className="btn btn-primary btn-xl"><Icons.Download/> Get Started Free</a>
                    <a href={GITHUB} target="_blank" rel="noreferrer" className="btn btn-outline btn-xl"><Icons.GitHub/> View on GitHub</a>
                  </div>
                  <div className="hero-pills au4">
                    {["MIT Licensed","Self-hosted","<10ms overhead","Any LLM"].map((p,i)=>(
                      <span key={i} className="hero-pill"><span className="hero-pill-dot"/>{p}</span>
                    ))}
                  </div>
                </div>

                {/* Preview card */}
                <div className="preview au2">
                  <div className="preview-bar">
                    <div className="preview-dot" style={{background:"#e63946"}}/>
                    <div className="preview-dot" style={{background:"#ffb703"}}/>
                    <div className="preview-dot" style={{background:"#2ecc71"}}/>
                    <span className="preview-title">tenet-ai — soc-dashboard</span>
                    <div className="preview-live"><div className="dot" style={{background:"var(--green)"}}/>LIVE</div>
                  </div>
                  <div className="preview-body">
                    <div className="p-stats">
                      <div className="p-stat"><div className="p-stat-v" style={{color:"var(--red)"}}>2,847</div><div className="p-stat-l">Blocked</div></div>
                      <div className="p-stat"><div className="p-stat-v" style={{color:"var(--amber)"}}>341</div><div className="p-stat-l">Flagged</div></div>
                      <div className="p-stat"><div className="p-stat-v" style={{color:"var(--green)"}}>98.7k</div><div className="p-stat-l">Allowed</div></div>
                    </div>
                    <LiveLog/>
                    <div className="p-bars">
                      <div className="p-bar-head">Attack Type Distribution</div>
                      {[["Prompt Injection",bars[0],"var(--red)"],["Jailbreak",bars[1],"var(--amber)"],["Data Extraction",bars[2],"var(--purple)"],["Role Manip.",bars[3],"var(--green)"]].map(([l,w,c],i)=>(
                        <div key={i} className="p-bar-row">
                          <span className="p-bar-lbl">{l}</span>
                          <div className="p-bar-track"><div className="p-bar-fill" style={{width:`${w}%`,background:c}}/></div>
                          <span className="p-bar-val">{w}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* STATS */}
          <section className="stats-strip">
            <div className="container">
              <div className="stats-grid">
                {[
                  {v:<><AnimNum to={parseInt(stars)||3}/></>,l:"GitHub Stars",s:"open source",c:"var(--cyan)"},
                  {v:"<10",l:"Detection ms",s:"heuristic layer",c:"var(--green)"},
                  {v:"90%+",l:"ML Accuracy",s:"on test set",c:"var(--purple)"},
                  {v:"4",l:"Attack Types",s:"covered out of box",c:"var(--amber)"},
                ].map((s,i)=>(
                  <FadeUp key={i} delay={i*0.07}>
                    <div className="stat-block">
                      <div className="stat-val" style={{color:s.c}}>{s.v}</div>
                      <div className="stat-lbl">{s.l}</div>
                      <div className="stat-sub">{s.s}</div>
                    </div>
                  </FadeUp>
                ))}
              </div>
            </div>
          </section>

          {/* HOW IT WORKS */}
          <section className="section">
            <div className="container">
              <FadeUp>
                <div style={{marginBottom:48}}>
                  <div className="eyebrow">Architecture</div>
                  <h2 className="section-title">How TENET AI <span className="grad">intercepts threats</span></h2>
                  <p className="section-sub">Four-stage pipeline adding &lt;10ms to every LLM request — invisible to users, visible to your security team.</p>
                </div>
              </FadeUp>
              <FadeUp delay={0.1}>
                <div className="how-grid">
                  <div className="how-line"/>
                  {[
                    {n:"⚡",tag:"STEP 1",title:"Intercept",desc:"Middleware captures all outbound prompts before they reach any LLM API endpoint."},
                    {n:"🔍",tag:"STEP 2",title:"Analyze",desc:"Heuristic rules, ML classifier, and behavioral engine run in parallel for full-spectrum coverage."},
                    {n:"🛡️",tag:"STEP 3",title:"Decide",desc:"Policy engine issues a verdict — Block / Sanitize / Flag / Allow — within the 10ms budget."},
                    {n:"🧠",tag:"STEP 4",title:"Learn",desc:"Analyst feedback and shared threat intelligence continuously improve detection accuracy."},
                  ].map((s,i)=>(
                    <div key={i} className="how-step">
                      <div className="how-num">{s.n}</div>
                      <div className="how-tag">{s.tag}</div>
                      <div className="how-title">{s.title}</div>
                      <div className="how-desc">{s.desc}</div>
                    </div>
                  ))}
                </div>
              </FadeUp>
            </div>
          </section>

          {/* FEATURES */}
          <section className="section section-alt">
            <div className="container">
              <FadeUp>
                <div style={{marginBottom:40}}>
                  <div className="eyebrow">Capabilities</div>
                  <h2 className="section-title">Everything to <span className="grad">secure your AI</span></h2>
                </div>
              </FadeUp>
              <div className="feat-grid">
                {FEATURES.map((f,i)=>(
                  <FadeUp key={i} delay={i*0.07}>
                    <div className="feat-card">
                      <div className="feat-icon" style={{background:f.bg}}>{f.icon}</div>
                      <div className="feat-title">{f.title}</div>
                      <div className="feat-desc">{f.desc}</div>
                      <div className="feat-tags">{f.tags.map((t,j)=><span key={j} className="tag" style={tagCss(t.c)}>{t.l}</span>)}</div>
                    </div>
                  </FadeUp>
                ))}
              </div>
            </div>
          </section>

          {/* CASE STUDIES */}
          <section className="section" id="threats">
            <div className="container">
              <FadeUp>
                <div style={{marginBottom:40}}>
                  <div className="eyebrow">Threat Intelligence</div>
                  <h2 className="section-title">Real breaches. <span className="grad">Real prevention.</span></h2>
                  <p className="section-sub">These incidents happened. The attack vectors are documented. TENET AI's pipeline would have blocked each one.</p>
                </div>
              </FadeUp>
              <div className="threat-list">
                {THREATS.map((t,i)=>(
                  <FadeUp key={i} delay={i*0.07}>
                    <div className="threat" style={{borderLeftColor:t.lc}}>
                      <div className="threat-meta">
                        <span className="threat-date">{t.date}</span>
                        <span className="threat-sev" style={{color:t.sc,background:t.sb}}>● {t.sev}</span>
                        <span className="threat-type">{t.type}</span>
                      </div>
                      <div>
                        <div className="threat-title">{t.title}</div>
                        <div className="threat-desc">{t.desc}</div>
                        <div className="threat-resp">
                          <div className="threat-resp-lbl">🛡 TENET AI RESPONSE</div>
                          <div className="threat-resp-text">{t.resp}</div>
                        </div>
                      </div>
                      <div className="threat-num">
                        <div className="threat-num-val" style={{color:t.sc}}>{t.stat}</div>
                        <div className="threat-num-lbl">{t.sl}</div>
                      </div>
                    </div>
                  </FadeUp>
                ))}
              </div>
            </div>
          </section>

          {/* INSTALL */}
          <section className="section section-alt" id="download">
            <div className="container">
              <FadeUp>
                <div style={{marginBottom:40}}>
                  <div className="eyebrow">Get Started</div>
                  <h2 className="section-title">Install in <span className="grad">minutes</span></h2>
                  <p className="section-sub">One additional API call. Zero changes to your LLM integration.</p>
                </div>
              </FadeUp>
              <div className="install-grid" style={{marginBottom:32}}>
                {INSTALLS.map((d,i)=>(
                  <FadeUp key={i} delay={i*0.07}>
                    <div className="install-card">
                      <div className="install-head">
                        <div>
                          <div className="install-icon">{d.icon}</div>
                          <div className="install-title">{d.title}</div>
                          <div className="install-sub">{d.sub}</div>
                        </div>
                        <span className="install-plat">{d.plat}</span>
                      </div>
                      <div className="install-cmd"><span className="install-prompt">$</span>{d.cmd}</div>
                      <div className="install-body">
                        <div className="install-features">{d.feats.map((f,j)=><div key={j} className="install-feat">{f}</div>)}</div>
                        <a href={GITHUB} target="_blank" rel="noreferrer" className="btn btn-outline btn-sm" style={{width:"100%",justifyContent:"center"}}><Icons.Download/> Download</a>
                      </div>
                    </div>
                  </FadeUp>
                ))}
              </div>
              <FadeUp delay={0.2}>
                <div className="code-block">
                  <div className="code-head">
                    <div className="code-dot2" style={{background:"#e63946"}}/>
                    <div className="code-dot2" style={{background:"#ffb703"}}/>
                    <div className="code-dot2" style={{background:"#2ecc71"}}/>
                    <span className="code-file">integration_example.py</span>
                    <span className="code-lang-badge">Python</span>
                  </div>
                  <div className="code-body">
                    <span className="cc"># 1. Install</span>{"\n"}
                    <span className="ck">import</span> <span className="cy">tenet_ai</span>{"\n\n"}
                    <span className="cc"># 2. Initialize</span>{"\n"}
                    <span>tenet</span> = tenet_ai.<span className="cf">Client</span>(<span>api_key</span>=<span className="cs">"your-key"</span>){"\n\n"}
                    <span className="cc"># 3. Intercept before any LLM call</span>{"\n"}
                    <span>result</span> = tenet.<span className="cf">check</span>(<span>prompt</span>=user_input, <span>user_id</span>=<span className="cs">"u-123"</span>){"\n\n"}
                    <span className="ck">if</span> <span>result</span>.blocked:{"\n"}
                    {"    "}<span className="ck">return</span> <span className="cs">"⛔ Blocked"</span>  <span className="cc"># &lt;5ms</span>{"\n\n"}
                    <span className="cc"># 4. Safe — call any LLM normally</span>{"\n"}
                    <span>response</span> = openai.<span className="cf">chat</span>(user_input)     <span className="cc"># OpenAI</span>{"\n"}
                    <span>response</span> = anthropic.<span className="cf">message</span>(user_input)  <span className="cc"># Claude</span>{"\n"}
                    <span>response</span> = ollama.<span className="cf">generate</span>(user_input)   <span className="cc"># Local</span>
                  </div>
                </div>
              </FadeUp>
            </div>
          </section>

          {/* CTA */}
          <section className="cta">
            <div className="cta-glow"/>
            <div className="container">
              <FadeUp>
                <h2 className="cta-title">Start protecting your<br/><span className="grad">AI applications today</span></h2>
                <p className="cta-sub">Self-hosted. Open source. Zero vendor lock-in.</p>
                <div className="cta-btns">
                  <a href="#download" className="btn btn-primary btn-xl"><Icons.Download/> Download Plugin</a>
                  <a href={GITHUB} target="_blank" rel="noreferrer" className="btn btn-outline btn-xl"><Icons.GitHub/> View on GitHub</a>
                </div>
                <div className="cta-chips">
                  {["MIT Licensed","Self-hosted option","Any LLM provider","No usage telemetry"].map((p,i)=>(
                    <span key={i} className="cta-chip">{p}</span>
                  ))}
                </div>
              </FadeUp>
            </div>
          </section>

        </main>

        {/* FOOTER */}
        <footer className="footer">
          <div className="container">
            <div className="footer-inner">
              <div className="footer-brand">
                <TenetLogo size={24}/>
                <span className="footer-name">TENET AI Dev</span>
              </div>
              <div className="footer-links">
                {[["GitHub",GITHUB],["Contributing",`${GITHUB}/blob/main/CONTRIBUTING.md`],["Security",`${GITHUB}/blob/main/SECURITY.md`],["Contact","mailto:saviodsouza8a@gmail.com"]].map(([l,h])=>(
                  <a key={l} href={h} target="_blank" rel="noreferrer" className="footer-link">{l}</a>
                ))}
              </div>
              <div className="footer-copy">Built by Savio D'souza · © 2026 MIT</div>
            </div>
          </div>
        </footer>

      </div>
    </>
  );
}
