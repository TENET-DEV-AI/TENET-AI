import { test, expect } from '@playwright/test';

const DASHBOARD_URL = 'http://localhost:5174';

test.describe('SOC Dashboard Authentication E2E Suite', () => {
  test.beforeEach(async ({ page }) => {
    // Clear storage before each auth test to ensure clean unauthenticated state
    await page.goto(DASHBOARD_URL);
    await page.evaluate(() => localStorage.clear());
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
  });

  test('should display SOC Login Portal when user is unauthenticated', async ({ page }) => {
    const loginPage = page.locator('[data-testid="soc-login-page"]');
    await expect(loginPage).toBeVisible();

    await expect(page.locator('.login-brand h2')).toHaveText('TENET AI Console');
    await expect(page.locator('.login-badge')).toContainText('RESTRICTED');
    await expect(page.locator('[data-testid="login-username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-password-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-role-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-submit-button"]')).toBeVisible();
  });

  test('should show validation error on empty credentials submission', async ({ page }) => {
    // 1. Clear both username and password -> asserts analyst email/ID is required
    await page.locator('[data-testid="login-username-input"]').fill('');
    await page.locator('[data-testid="login-password-input"]').fill('');
    await page.locator('[data-testid="login-submit-button"]').click();

    const errorAlert = page.locator('[data-testid="login-error-message"]');
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText('Analyst email or ID is required.');

    // 2. Fill username with empty password -> asserts password is required
    await page.locator('[data-testid="login-username-input"]').fill('analyst@tenet.ai');
    await page.locator('[data-testid="login-submit-button"]').click();
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText('Password is required.');
  });

  test('should show error when invalid password is entered', async ({ page }) => {
    await page.locator('[data-testid="login-username-input"]').fill('analyst@tenet.ai');
    await page.locator('[data-testid="login-password-input"]').fill('123'); // too short / invalid
    await page.locator('[data-testid="login-submit-button"]').click();

    const errorAlert = page.locator('[data-testid="login-error-message"]');
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText(/Invalid credentials/i);
  });

  test('should autofill credentials using Demo Credentials button', async ({ page }) => {
    await page.locator('[data-testid="login-username-input"]').fill('');
    await page.locator('[data-testid="login-password-input"]').fill('');

    await page.locator('[data-testid="login-demo-credentials-btn"]').click();

    await expect(page.locator('[data-testid="login-username-input"]')).toHaveValue('analyst@tenet.ai');
    await expect(page.locator('[data-testid="login-password-input"]')).toHaveValue('password123');
  });

  test('should successfully log in, display user in sidebar, and persist across reload', async ({ page }) => {
    // Fill credentials
    await page.locator('[data-testid="login-demo-credentials-btn"]').click();
    await page.locator('[data-testid="login-submit-button"]').click();

    // Verify redirected into SOC dashboard
    const dashboardApp = page.locator('[data-testid="soc-dashboard-app"]');
    await expect(dashboardApp).toBeVisible();

    // Verify sidebar shows user details
    const userEmail = page.locator('[data-testid="user-email"]');
    await expect(userEmail).toBeVisible();
    await expect(userEmail).toHaveText('analyst@tenet.ai');

    const logoutBtn = page.locator('[data-testid="logout-button"]');
    await expect(logoutBtn).toBeVisible();

    // Verify session persistence on page reload
    await page.reload();
    await expect(dashboardApp).toBeVisible();
    await expect(userEmail).toHaveText('analyst@tenet.ai');
  });

  test('should successfully sign out and return to login screen', async ({ page }) => {
    // Log in first
    await page.locator('[data-testid="login-demo-credentials-btn"]').click();
    await page.locator('[data-testid="login-submit-button"]').click();
    await expect(page.locator('[data-testid="soc-dashboard-app"]')).toBeVisible();

    // Click logout button
    await page.locator('[data-testid="logout-button"]').click();

    // Verify redirected back to Login portal
    await expect(page.locator('[data-testid="soc-login-page"]')).toBeVisible();

    // Reload to verify logged-out state persists
    await page.reload();
    await expect(page.locator('[data-testid="soc-login-page"]')).toBeVisible();
  });
});
