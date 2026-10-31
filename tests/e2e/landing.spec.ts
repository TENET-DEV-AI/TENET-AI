import { test, expect } from '@playwright/test';

const LANDING_URL = 'http://localhost:5173';

test.describe('Landing Page E2E Suite', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(LANDING_URL);
    await page.waitForLoadState('domcontentloaded');
  });

  test('should load landing page with correct title and branding', async ({ page }) => {
    await expect(page).toHaveTitle(/TENET/i);
    const brand = page.locator('.brand-name');
    await expect(brand).toBeVisible();
    await expect(brand).toContainText('TENET AI');

    const versionBadge = page.locator('.brand-badge');
    await expect(versionBadge).toBeVisible();
    await expect(versionBadge).toHaveText('v0.1');

    const liveBadge = page.locator('.live-badge');
    await expect(liveBadge).toBeVisible();
    await expect(liveBadge).toContainText('LIVE');
  });

  test('should navigate to sections via desktop navbar links', async ({ page }) => {
    const navItems = [
      { id: 'pipeline', label: 'Pipeline' },
      { id: 'features', label: 'Features' },
      { id: 'demo', label: 'Sandbox' },
      { id: 'compare', label: 'Comparison' },
      { id: 'threats', label: 'Case Studies' },
      { id: 'download', label: 'Install' },
    ];

    for (const item of navItems) {
      const link = page.locator(`.nav a[href="#${item.id}"]`);
      await expect(link).toBeVisible();
      await link.click();

      const targetSection = page.locator(`#${item.id}`);
      await expect(targetSection).toBeInViewport();
    }
  });

  test('should test hero and CTA buttons navigation', async ({ page }) => {
    // Hero Primary CTA -> scrolls to #download
    const getStartedBtn = page.locator('.hero-actions a.btn-primary');
    await expect(getStartedBtn).toBeVisible();
    await expect(getStartedBtn).toContainText('Get Started Free');
    await getStartedBtn.click();
    await expect(page.locator('#download')).toBeInViewport();

    // Hero Secondary CTA -> External GitHub link
    const githubBtn = page.locator('.hero-actions a[href*="github.com"]');
    await expect(githubBtn).toBeVisible();
    await expect(githubBtn).toHaveAttribute('target', '_blank');
    await expect(githubBtn).toHaveAttribute('href', 'https://github.com/TENET-DEV-AI/TENET-AI');

    // Bottom CTA section button
    const downloadSdkBtn = page.locator('.cta-btns a.btn-primary');
    await expect(downloadSdkBtn).toBeVisible();
    await expect(downloadSdkBtn).toContainText('Download SDK');
    await downloadSdkBtn.click();
    await expect(page.locator('#download')).toBeInViewport();
  });

  test('should interact with Interactive Threat Sandbox tabs', async ({ page }) => {
    const sandboxSection = page.locator('#demo');
    await sandboxSection.scrollIntoViewIfNeeded();
    await expect(sandboxSection).toBeVisible();

    // Tab list of attacks
    const attackTabs = page.locator('.demo-attack-btn');
    await expect(attackTabs).toHaveCount(4);

    // Click Jailbreak tab
    const jailbreakTab = attackTabs.filter({ hasText: 'Jailbreak' });
    await jailbreakTab.click();
    await expect(jailbreakTab).toHaveAttribute('aria-selected', 'true');

    // Click Data Extraction tab
    const extractionTab = attackTabs.filter({ hasText: 'Data Extraction' });
    await extractionTab.click();
    await expect(extractionTab).toHaveAttribute('aria-selected', 'true');

    // Click Prompt Injection tab
    const injectionTab = attackTabs.filter({ hasText: 'Prompt Injection' });
    await injectionTab.click();
    await expect(injectionTab).toHaveAttribute('aria-selected', 'true');
  });

  test('should toggle mobile navigation menu on small viewports', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });

    const hamburgerBtn = page.locator('.hamburger-btn');
    await expect(hamburgerBtn).toBeVisible();

    // Open mobile menu
    await hamburgerBtn.click();
    const mobileMenu = page.locator('.mobile-menu');
    await expect(mobileMenu).toHaveClass(/open/);

    // Test navigation item in mobile drawer
    const mobileNavLink = page.locator('.mobile-menu-link[href="#features"]');
    await expect(mobileNavLink).toBeVisible();
    await mobileNavLink.click();

    // Drawer should close after clicking link
    await expect(mobileMenu).not.toHaveClass(/open/);
  });
});
