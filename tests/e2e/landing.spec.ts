import { test, expect } from '@playwright/test';

const LANDING_URL = 'http://localhost:5173';

test.describe('Landing Page E2E Suite', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(LANDING_URL);
    await page.waitForLoadState('domcontentloaded');
  });

  test('loads with the masthead identity and issue line', async ({ page }) => {
    await expect(page).toHaveTitle(/TENET/i);

    const wordmark = page.locator('.top .wordmark');
    await expect(wordmark).toBeVisible();
    await expect(wordmark).toContainText('TENET');
    await expect(wordmark).toContainText('defensive middleware');

    await expect(page.locator('.top .issue')).toContainText('No. 04');
    await expect(page.locator('.top .cta')).toContainText('pip install tenet-ai');
  });

  test('navigates to each section from the masthead', async ({ page }) => {
    const sections = [
      { id: 'classes', label: 'Classes' },
      { id: 'product', label: 'Console' },
      { id: 'architecture', label: 'Architecture' },
      { id: 'bench', label: 'Test bench' },
      { id: 'reports', label: 'Reports' },
      { id: 'install', label: 'Install' },
    ];

    for (const section of sections) {
      // The masthead tucks away once you scroll; bring it back before each click.
      await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'auto' }));
      await expect(page.locator('.top')).not.toHaveClass(/hide/);

      const link = page.locator(`.top .top-in nav a[href="#${section.id}"]`);
      await expect(link).toHaveText(section.label);
      await link.click();
      await expect(page.locator(`#${section.id}`)).toBeInViewport();
    }
  });

  test('hero calls to action reach install and the test bench', async ({ page }) => {
    const installCta = page.locator('.hero .actions a.btn');
    await expect(installCta).toContainText('Install tenet-ai');
    await installCta.click();
    await expect(page.locator('#install')).toBeInViewport();

    const benchLink = page.locator('.hero .actions a.tlink');
    await expect(benchLink).toContainText('Try a payload');
    await benchLink.click();
    await expect(page.locator('#bench')).toBeInViewport();
  });

  test('colour scheme toggle switches paper and ink', async ({ page }) => {
    const html = page.locator('html');
    const toggle = page.locator('#themeBtn');
    await expect(toggle).toBeVisible();

    const before = await html.getAttribute('data-theme');
    await toggle.click();
    const after = await html.getAttribute('data-theme');

    expect(after).not.toBe(before);
    expect(['light', 'dark']).toContain(after);
    await expect(toggle).toHaveAttribute('aria-pressed', after === 'dark' ? 'true' : 'false');
  });

  test('test bench scores a payload against the local rule engine', async ({ page }) => {
    const bench = page.locator('#bench');
    await bench.scrollIntoViewIfNeeded();

    const presets = page.locator('.bench-btn');
    await expect(presets).toHaveCount(5);

    // Choosing a preset fills the payload and produces a verdict.
    const jailbreak = presets.filter({ hasText: 'Jailbreak' });
    await jailbreak.click();
    await expect(jailbreak).toHaveAttribute('aria-pressed', 'true');

    const verdict = page.locator('#vAction');
    await expect(verdict).toHaveText(/Blocked|Flagged|Allowed/, { timeout: 10000 });
    await expect(page.locator('#vRisk')).not.toHaveText('—');
    await expect(page.locator('#pInput')).toHaveValue(/Do Anything Now/);
  });

  test('opens and closes the mobile section sheet', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });

    const burger = page.locator('#burger');
    await expect(burger).toBeVisible();
    await expect(burger).toHaveAttribute('aria-expanded', 'false');

    await burger.click();
    const sheet = page.locator('#mnav');
    await expect(sheet).toBeVisible();
    await expect(sheet).toHaveClass(/open/);
    await expect(burger).toHaveAttribute('aria-expanded', 'true');

    await sheet.locator('a[href="#product"]').click();
    await expect(sheet).not.toHaveClass(/open/);
    await expect(page.locator('#product')).toBeInViewport();
  });
});
