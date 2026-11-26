import { test, expect } from '@playwright/test';

const DASHBOARD_URL = 'http://localhost:5174';

test.describe('SOC Console Alert Management E2E Suite', () => {
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

    // The queue is the triage surface: rail → Triage queue
    await page.locator('.rail .nav a').filter({ hasText: 'Triage queue' }).click();
    await expect(page.locator('.qlist')).toBeVisible();
  });

  test('lists open alerts with a workflow badge', async ({ page }) => {
    const rows = page.locator('.qitem');
    await expect(rows.first()).toBeVisible();
    await expect(page.locator('[data-testid^="status-badge-"]').first()).toBeVisible();
  });

  test('opens the investigation modal and reads the payload', async ({ page }) => {
    await page.locator('[data-testid^="view-alert-btn-"]').first().click();

    const modal = page.locator('[data-testid="alert-detail-modal"]');
    await expect(modal).toBeVisible();
    await expect(page.locator('[data-testid="modal-alert-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="modal-workflow-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="modal-prompt-content"]')).toBeVisible();

    await page.locator('[data-testid="modal-close-button"]').click();
    await expect(modal).not.toBeVisible();
  });

  test('acknowledges an alert and flips its badge', async ({ page }) => {
    const ackBtn = page.locator('[data-testid^="ack-alert-btn-"]').first();
    await expect(ackBtn).toBeVisible();
    const testId = await ackBtn.getAttribute('data-testid');
    const eventId = testId!.replace('ack-alert-btn-', '');

    await ackBtn.click();

    const badge = page.locator(`[data-testid="status-badge-${eventId}"]`);
    await expect(badge).toHaveClass(/status-acknowledged/);
    await expect(badge).toContainText('acknowledged');
  });

  test('resolves an alert from the investigation modal with a note', async ({ page }) => {
    await page.locator('[data-testid^="view-alert-btn-"]').first().click();

    const modal = page.locator('[data-testid="alert-detail-modal"]');
    await expect(modal).toBeVisible();

    await page.locator('[data-testid="modal-resolve-btn"]').click();

    const noteInput = page.locator('[data-testid="resolution-note-input"]');
    await expect(noteInput).toBeVisible();
    await noteInput.fill('Verified and quarantined the attacking agent session.');

    await page.locator('[data-testid="modal-confirm-resolve-btn"]').click();

    const modalStatus = page.locator('[data-testid="modal-workflow-status"]');
    await expect(modalStatus).toHaveClass(/status-resolved/);
    await expect(modalStatus).toContainText('resolved');

    await page.locator('[data-testid="modal-dismiss-btn"]').click();
    await expect(modal).not.toBeVisible();
  });

  test('marks an alert as a false positive', async ({ page }) => {
    const firstRow = page.locator('.qitem').first();
    const fpBtn = firstRow.locator('[data-testid^="feedback-fp-"]');
    await expect(fpBtn).toBeVisible();
    await fpBtn.click();

    await expect(firstRow).toContainText('Marked as False Positive');
  });
});
