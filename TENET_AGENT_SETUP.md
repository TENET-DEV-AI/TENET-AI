# 🛡️ TENET Agent – Setup & Deployment Guide

A self-hosted AI agent for `AI-Cyber-Defender` that reviews PRs and autonomously fixes issues.

---

## ⚡ Quick Setup (5 minutes)

### Step 1 — Copy files into your repo

Copy the following files from this directory into your `AI-Cyber-Defender` repository, preserving the directory structure:

```
.github/
├── workflows/
│   ├── tenet-pr-review.yml       ← PR reviewer workflow
│   └── tenet-issue-solver.yml    ← Issue solver workflow
├── tenet_agent/
│   ├── requirements.txt
│   ├── utils.py
│   ├── prompts.py
│   ├── tenet_review.py
│   └── tenet_solve.py
└── pull_request_template.md      ← Updated template
```

### Step 2 — Add the LLM secret

1. Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `TENET_AI_KEY`
4. Value: Your **Google Gemini API key** (get one free at [aistudio.google.com](https://aistudio.google.com))
5. Click **Add secret**

> `GITHUB_TOKEN` is **automatically** provided by GitHub Actions — no action needed.

### Step 3 — Create the `tenet-agent` label (optional but recommended)

Go to **Issues** → **Labels** → **New label**:
- Name: `tenet-agent`
- Color: `#0075ca`
- Description: `Managed by TENET Agent`

Also create `🚨 security` label if it doesn't exist.

### Step 4 — Push and test

```bash
git add .github/
git commit -m "feat: add TENET Agent (issue #44)"
git push
```

---

## 🎮 Usage

### Mode 1: Automatic PR Review
Every time a PR is opened or updated → TENET Agent automatically posts a security review.

No action needed. Just open a PR.

### Mode 2: Issue Auto-Fix (Maintainers Only)
1. Find any open issue
2. Comment (as a maintainer): `/tenet fix`
3. TENET Agent will:
   - React with 👀
   - Post a "working on it" comment
   - Analyze the codebase
   - Generate a fix
   - Push branch `tenet/fix-issue-{N}`
   - Open a PR with `Closes #N`
   - Post a summary comment on the issue

---

## 🔐 Permission Model

| Action | Who can trigger it |
|---|---|
| PR review | Automatic — any PR |
| `/tenet fix` | **Admin or Write** collaborators only |
| Push branch + open PR | `GITHUB_TOKEN` (scoped to the Actions runner) |

---

## 🔧 Configuration

Edit `.github/tenet_agent/prompts.py` to customize:
- **PR review focus** — add/remove security checks
- **Code style preferences** — tell the LLM your coding standards
- **Issue solver context** — add project-specific guidelines

To switch to **OpenAI GPT-4o** instead of Gemini:
1. In `utils.py`, replace `get_llm_client()` to use the `openai` library
2. Rename the secret to `OPENAI_API_KEY` (or keep `TENET_AI_KEY`)

---

## 🏗️ Architecture

```
issue_comment event (/tenet fix)
        │
        ▼
tenet-issue-solver.yml
        │
        ├─ Permission check (Admin/Write only)
        ├─ React 👀, assign bot
        ├─ Checkout repo
        │
        ├─ tenet_solve.py
        │       ├─ Phase 1: Gemini analyzes issue + repo context
        │       ├─ Phase 2: Gemini generates code fix
        │       ├─ Parse FILE blocks → {filepath: content}
        │       ├─ git checkout -b tenet/fix-issue-{N}
        │       ├─ Commit + push
        │       └─ Open PR + post issue comment
        │
pull_request event (opened/updated)
        │
        ▼
tenet-pr-review.yml
        │
        └─ tenet_review.py
                ├─ Fetch PR diff via GitHub API
                ├─ Gemini: security review prompt
                ├─ Post review comment on PR
                └─ Add 🚨 security label if critical/high findings
```
