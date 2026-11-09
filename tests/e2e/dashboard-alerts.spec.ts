import { test, expect } from '@playwright/test';

const DASHBOARD_URL = 'http://localhost:5174';

test.describe('SOC Dashboard Alert Management E2E Suite', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate with auth pre-set or log in
    await page.goto(DASHBOARD_URL);
    await page.evaluate(() => {
      localStorage.setItem('tenet_soc_user', JSON.stringify({
        email: 'analyst@tenet.ai',
        role: 'Senior SOC Responder',
        token: 'test_token',
      }));
    });
    await page.reload();
    await page.waitForLoadState('domcontentloaded');

    // Switch to Alert Feed tab
    const alertFeedNav = page.locator('nav button').filter({ hasText: 'Alert Feed' });
    await alertFeedNav.click();
    await expect(page.locator('.events-list')).toBeVisible();
  });

  test('should display alert list with initial workflow statuses', async ({ page }) => {
    const alertRows = page.locator('tbody tr');
    await expect(alertRows.first()).toBeVisible();

    // Check status badges exist
    const statusBadges = page.locator('[data-testid^="status-badge-"]');
    await expect(statusBadges.first()).toBeVisible();
  });

  test('should open alert investigation modal and view forensic payload', async ({ page }) => {
    // Click View on first alert
    const firstViewBtn = page.locator('[data-testid^="view-alert-btn-"]').first();
    await firstViewBtn.click();

    // Modal dialog should appear
    const modal = page.locator('[data-testid="alert-detail-modal"]');
    await expect(modal).toBeVisible();

    // Verify modal fields
    await expect(page.locator('[data-testid="modal-alert-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="modal-workflow-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="modal-prompt-content"]')).toBeVisible();

    // Test close button
    const closeBtn = page.locator('[data-testid="modal-close-button"]');
    await closeBtn.click();
    await expect(modal).not.toBeVisible();
  });

  test('should acknowledge an alert and update status badge to Acknowledged', async ({ page }) => {
    // Find the first acknowledge button and extract its event ID
    const ackBtn = page.locator('[data-testid^="ack-alert-btn-"]').first();
    await expect(ackBtn).toBeVisible();
    const testId = await ackBtn.getAttribute('data-testid');
    const eventId = testId!.replace('ack-alert-btn-', '');

    // Click Acknowledge
    await ackBtn.click();

    // The status badge for this specific event ID should now be Acknowledged
    const updatedBadge = page.locator(`[data-testid="status-badge-${eventId}"]`);
    await expect(updatedBadge).toHaveClass(/status-acknowledged/);
    await expect(updatedBadge).toContainText('Acknowledged');
  });

  test('should resolve an alert from investigation modal and verify resolution state', async ({ page }) => {
    // Open modal on first alert
    const viewBtn = page.locator('[data-testid^="view-alert-btn-"]').first();
    await viewBtn.click();

    const modal = page.locator('[data-testid="alert-detail-modal"]');
    await expect(modal).toBeVisible();

    // Click Resolve Alert in modal (first alert is unresolved, so resolve button must be visible)
    const resolveBtn = page.locator('[data-testid="modal-resolve-btn"]');
    await expect(resolveBtn).toBeVisible();
    await resolveBtn.click();

    // Enter resolution note
    const noteInput = page.locator('[data-testid="resolution-note-input"]');
    await expect(noteInput).toBeVisible();
    await noteInput.fill('Verified and quarantined attacking agent session.');

    // Confirm resolution
    const confirmBtn = page.locator('[data-testid="modal-confirm-resolve-btn"]');
    await confirmBtn.click();

    // Modal workflow badge should update to Resolved
    const modalStatus = page.locator('[data-testid="modal-workflow-status"]');
    await expect(modalStatus).toHaveClass(/status-resolved/);
    await expect(modalStatus).toContainText('Resolved');

    // Close modal
    await page.locator('[data-testid="modal-dismiss-btn"]').click();
    await expect(modal).not.toBeVisible();
  });

  test('should mark false positive and false negative analyst feedback', async ({ page }) => {
    const firstRow = page.locator('tbody tr').first();
    const fpBtn = firstRow.locator('[data-testid^="feedback-fp-"]');
    await expect(fpBtn).toBeVisible();
    await fpBtn.click();

    // Feedback message appears
    await expect(firstRow).toContainText('Marked as False Positive');
  });
});
