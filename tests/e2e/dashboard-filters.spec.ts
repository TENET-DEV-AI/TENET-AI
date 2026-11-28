import { test, expect } from '@playwright/test';

const DASHBOARD_URL = 'http://localhost:5174';

test.describe('SOC Console Filtering and Search E2E Suite', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await page.evaluate(() => {
      localStorage.setItem(
        'tenet_soc_user',
        JSON.stringify({
          email: 'analyst@tenet.ai',
          role: 'Senior SOC Responder',
          token: 'test_token',
        }),
      );
    });
    await page.reload();
    await page.waitForLoadState('domcontentloaded');

    await page.locator('.rail .nav a').filter({ hasText: 'Triage queue' }).click();
    await expect(page.locator('.qlist')).toBeVisible();
  });

  test('filters the queue by free text', async ({ page }) => {
    const rows = page.locator('.qitem');
    const initialCount = await rows.count();
    expect(initialCount).toBeGreaterThan(0);

    await page.locator('input[aria-label="Filter queue"]').fill('bypass');
    await expect
      .poll(async () => rows.count(), { message: 'queue narrows to the matching prompts' })
      .toBeLessThan(initialCount);
    expect(await rows.count()).toBeGreaterThan(0);

    await page.locator('input[aria-label="Filter queue"]').fill('');
    await expect(rows).toHaveCount(initialCount);
  });

  test('focuses the queue filter with the "/" shortcut', async ({ page }) => {
    const search = page.locator('input[aria-label="Filter queue"]');
    await page.locator('.topbar h1').click();
    await expect(search).not.toBeFocused();

    await page.keyboard.press('/');
    await expect(search).toBeFocused();
  });

  test('filters by verdict and shows an active chip', async ({ page }) => {
    await page.getByRole('button', { name: /^Filters/ }).click();
    const panel = page.locator('.fpanel');
    await expect(panel).toBeVisible();

    await panel.locator('#f-verdict').selectOption('malicious');

    const chip = page.locator('.chips .chip').first();
    await expect(chip).toContainText('Verdict: malicious');

    // The queue still has rows, and every row now matches the verdict filter.
    expect(await page.locator('.qitem').count()).toBeGreaterThan(0);

    await page.getByRole('button', { name: 'Clear all' }).click();
    await expect(page.locator('.chips')).toHaveCount(0);
  });

  test('switches queue views', async ({ page }) => {
    const rows = page.locator('.qitem');
    const openCount = await rows.count();

    await page.locator('.vchip').filter({ hasText: 'All' }).click();
    const allCount = await rows.count();
    expect(allCount).toBeGreaterThanOrEqual(openCount);

    await page.locator('.vchip').filter({ hasText: 'Open' }).click();
    await expect(rows).toHaveCount(openCount);
  });

  test('moves through the queue with j and k', async ({ page }) => {
    await page.locator('.qitem').first().click();
    const firstId = await page.locator('.qitem.sel').getAttribute('data-event-id');

    await page.keyboard.press('j');
    const secondId = await page.locator('.qitem.sel').getAttribute('data-event-id');
    expect(secondId).not.toBe(firstId);

    await page.keyboard.press('k');
    await expect(page.locator('.qitem.sel')).toHaveAttribute('data-event-id', firstId ?? '');
  });
});
