import { test, expect } from '@playwright/test';

const DASHBOARD_URL = 'http://localhost:5174';

test.describe('SOC Console Authentication E2E Suite', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await page.evaluate(() => localStorage.clear());
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
  });

  test('shows the analyst sign-in portal when unauthenticated', async ({ page }) => {
    const loginPage = page.locator('[data-testid="soc-login-page"]');
    await expect(loginPage).toBeVisible();

    await expect(page.locator('.auth .card h1')).toHaveText('TENET AI Console');
    await expect(page.locator('.auth .badge').first()).toContainText('Restricted');
    await expect(page.locator('[data-testid="login-username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-password-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-role-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-submit-button"]')).toBeVisible();
  });

  test('validates empty credentials', async ({ page }) => {
    await page.locator('[data-testid="login-username-input"]').fill('');
    await page.locator('[data-testid="login-password-input"]').fill('');
    await page.locator('[data-testid="login-submit-button"]').click();

    const errorAlert = page.locator('[data-testid="login-error-message"]');
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText('Analyst email or ID is required.');

    await page.locator('[data-testid="login-username-input"]').fill('analyst@tenet.ai');
    await page.locator('[data-testid="login-submit-button"]').click();
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText('Password is required.');
  });

  test('rejects an invalid password', async ({ page }) => {
    await page.locator('[data-testid="login-username-input"]').fill('analyst@tenet.ai');
    await page.locator('[data-testid="login-password-input"]').fill('123');
    await page.locator('[data-testid="login-submit-button"]').click();

    const errorAlert = page.locator('[data-testid="login-error-message"]');
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText(/Invalid credentials/i);
  });

  test('fills demo credentials on request', async ({ page }) => {
    await page.locator('[data-testid="login-username-input"]').fill('');
    await page.locator('[data-testid="login-password-input"]').fill('');

    await page.locator('[data-testid="login-demo-credentials-btn"]').click();

    await expect(page.locator('[data-testid="login-username-input"]')).toHaveValue('analyst@tenet.ai');
    await expect(page.locator('[data-testid="login-password-input"]')).toHaveValue('password123');
  });

  test('signs in, shows the analyst in the rail, and survives a reload', async ({ page }) => {
    await page.locator('[data-testid="login-demo-credentials-btn"]').click();
    await page.locator('[data-testid="login-submit-button"]').click();

    const console_ = page.locator('[data-testid="soc-dashboard-app"]');
    await expect(console_).toBeVisible();

    const userEmail = page.locator('[data-testid="user-email"]');
    await expect(userEmail).toBeVisible();
    await expect(userEmail).toHaveText('analyst@tenet.ai');
    await expect(page.locator('[data-testid="logout-button"]')).toBeVisible();

    await page.reload();
    await expect(console_).toBeVisible();
    await expect(userEmail).toHaveText('analyst@tenet.ai');
  });

  test('signs out and returns to the portal', async ({ page }) => {
    await page.locator('[data-testid="login-demo-credentials-btn"]').click();
    await page.locator('[data-testid="login-submit-button"]').click();
    await expect(page.locator('[data-testid="soc-dashboard-app"]')).toBeVisible();

    await page.locator('[data-testid="logout-button"]').click();
    await expect(page.locator('[data-testid="soc-login-page"]')).toBeVisible();

    await page.reload();
    await expect(page.locator('[data-testid="soc-login-page"]')).toBeVisible();
  });
});
