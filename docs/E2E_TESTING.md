# End-to-End (E2E) Testing Guide

TENET AI uses [Playwright](https://playwright.dev/) for automated end-to-end (E2E) and visual regression testing across the **Landing Page** (`http://localhost:5173`) and the **SOC Dashboard** (`http://localhost:5174`).

---

## 🏗️ Architecture Overview

The E2E test suites validate complete user journeys across both frontends:

| Test Suite | File | Focus Areas |
|------------|------|-------------|
| **Landing Page** | `tests/e2e/landing.spec.ts` | Navigation links, CTAs, Sandbox attack scenarios, Mobile drawer |
| **SOC Auth** | `tests/e2e/dashboard-auth.spec.ts` | Unauthenticated portal, validation, demo login, session persistence, logout |
| **Alert Management** | `tests/e2e/dashboard-alerts.spec.ts` | Alert feed, forensic investigation modal, acknowledge & resolve workflow |
| **Dashboard Filters** | `tests/e2e/dashboard-filters.spec.ts` | Search queries, shortcut keys (`/`), status & severity filters, presets, chart routing |
| **Visual Regression** | `tests/e2e/visual-regression.spec.ts` | Pixel-level screenshot comparisons for landing and dashboard components |

---

## 🚀 Quickstart

### 1. Prerequisites

Ensure you have **Node.js 20.19+** or **22.12+** installed.

```bash
node -v
npm -v
```

### 2. Install Dependencies

Install dependencies for the root test runner and both applications:

```bash
# Install root E2E dependencies
npm install

# Install dashboard dependencies
npm --prefix dashboard install

# Install landing page dependencies
npm --prefix landing install

# Install Playwright browser binaries
npx playwright install chromium
```

---

## 🧪 Running Tests Locally

Playwright automatically boots both Vite dev servers (`landing` on `5173`, `dashboard` on `5174`) before running tests and tears them down afterward (when running locally, existing servers running on these ports are reused and left running).

### Run All E2E Tests

```bash
npm run test:e2e
```

### Run by Specific Suite

```bash
# Landing page tests
npm run test:e2e:landing

# SOC Dashboard authentication & login tests
npx playwright test tests/e2e/dashboard-auth.spec.ts

# Alert management (view, acknowledge, resolve) tests
npx playwright test tests/e2e/dashboard-alerts.spec.ts

# Dashboard search, filters, and presets tests
npx playwright test tests/e2e/dashboard-filters.spec.ts
```

### Interactive UI Mode

Inspect locators, step through tests, and time-travel debug with the Playwright UI:

```bash
npm run test:e2e:ui
```

### Headed Mode (Watch in Real Browser)

```bash
npm run test:e2e:headed
```

### Visual Regression Snapshots

To run screenshot comparison tests and generate or update baseline golden snapshots:

```bash
# Run visual comparisons
npm run test:e2e:visual

# Update baseline screenshots
npx playwright test tests/e2e/visual-regression.spec.ts --update-snapshots
```

### View HTML Test Report

After running tests, view detailed step-by-step traces, failure screenshots, and videos:

```bash
npx playwright show-report
```

---

## 🔄 Continuous Integration (CI)

Playwright E2E tests are configured in `.github/workflows/ci.yml` and run automatically on every Pull Request to `main`. If any test fails, Playwright traces and failure screenshots are archived in GitHub Actions artifacts for 14 days.
