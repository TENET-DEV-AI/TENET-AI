import { test, expect } from '@playwright/test';

const LANDING_URL = 'http://localhost:5173';
const DASHBOARD_URL = 'http://localhost:5174';

test.describe('Visual Regression Testing Suite', () => {
  test('landing page desktop hero snapshot', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto(LANDING_URL);
    await page.waitForLoadState('networkidle');

    // Screenshot of hero section
    const hero = page.locator('#home');
    await expect(hero).toBeVisible();
    await expect(hero).toHaveScreenshot('landing-hero.png', {
      maxDiffPixelRatio: 0.05,
      animations: 'disabled',
    });
  });

  test('landing page interactive sandbox snapshot', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto(LANDING_URL);
    await page.waitForLoadState('networkidle');

    const sandbox = page.locator('#demo');
    await sandbox.scrollIntoViewIfNeeded();
    await expect(sandbox).toBeVisible();
    await expect(sandbox).toHaveScreenshot('landing-sandbox.png', {
      maxDiffPixelRatio: 0.05,
      animations: 'disabled',
    });
  });

  test('landing page mobile viewport snapshot', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(LANDING_URL);
    await page.waitForLoadState('networkidle');

    await expect(page).toHaveScreenshot('landing-mobile.png', {
      maxDiffPixelRatio: 0.05,
      animations: 'disabled',
      fullPage: false,
    });
  });

  test('soc dashboard login portal snapshot', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto(DASHBOARD_URL);
    await page.evaluate(() => localStorage.clear());
    await page.reload();
    await page.waitForLoadState('networkidle');

    const loginCard = page.locator('.login-card');
    await expect(loginCard).toBeVisible();
    await expect(loginCard).toHaveScreenshot('dashboard-login-card.png', {
      maxDiffPixelRatio: 0.05,
      animations: 'disabled',
    });
  });

  test('soc dashboard main overview snapshot', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto(DASHBOARD_URL);
    await page.evaluate(() => {
      localStorage.setItem('tenet_soc_user', JSON.stringify({
        email: 'analyst@tenet.ai',
        role: 'Senior SOC Responder',
        token: 'test_token',
      }));
    });
    await page.reload();
    await page.waitForLoadState('networkidle');

    const statCards = page.locator('.stat-cards');
    await expect(statCards).toBeVisible();
    await expect(statCards).toHaveScreenshot('dashboard-stats.png', {
      maxDiffPixelRatio: 0.05,
      animations: 'disabled',
    });
  });

  test('soc alert feed table snapshot', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto(DASHBOARD_URL);
    await page.evaluate(() => {
      localStorage.setItem('tenet_soc_user', JSON.stringify({
        email: 'analyst@tenet.ai',
        role: 'Senior SOC Responder',
        token: 'test_token',
      }));
    });
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Switch to Alert Feed
    await page.locator('nav button').filter({ hasText: 'Alert Feed' }).click();
    const table = page.locator('.table-container');
    await expect(table).toBeVisible();
    await expect(table).toHaveScreenshot('alert-feed-table.png', {
      maxDiffPixelRatio: 0.05,
      animations: 'disabled',
    });
  });

  test('soc alert investigation modal snapshot', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto(DASHBOARD_URL);
    await page.evaluate(() => {
      localStorage.setItem('tenet_soc_user', JSON.stringify({
        email: 'analyst@tenet.ai',
        role: 'Senior SOC Responder',
        token: 'test_token',
      }));
    });
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Switch to Alert Feed and open modal
    await page.locator('nav button').filter({ hasText: 'Alert Feed' }).click();
    await page.locator('[data-testid^="view-alert-btn-"]').first().click();

    const modal = page.locator('[data-testid="alert-detail-modal"]');
    await expect(modal).toBeVisible();
    await expect(modal).toHaveScreenshot('alert-investigation-modal.png', {
      maxDiffPixelRatio: 0.05,
      animations: 'disabled',
    });
  });
});
