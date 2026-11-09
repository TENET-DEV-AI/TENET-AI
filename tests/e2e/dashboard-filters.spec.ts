import { test, expect } from '@playwright/test';

const DASHBOARD_URL = 'http://localhost:5174';

test.describe('SOC Dashboard Filtering and Search E2E Suite', () => {
  test.beforeEach(async ({ page }) => {
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

  test('should search events by prompt keywords and update results count', async ({ page }) => {
    const searchInput = page.locator('input[aria-label="Search events"]');
    await expect(searchInput).toBeVisible();

    const rows = page.locator('tbody tr');
    const initialRowCount = await rows.count();

    // Type search query
    await searchInput.fill('bypass');

    // Verify filtered table only shows matching results
    await expect(rows.first()).toBeVisible();
    await expect(rows.first()).toContainText(/bypass/i);

    // Verify export count updates
    await expect(page.locator('.export-count')).toHaveText('2 events');

    // Clear search and verify full list is restored
    await searchInput.fill('');
    await expect(rows).toHaveCount(initialRowCount);
  });

  test('should focus search input when pressing shortcut key "/"', async ({ page }) => {
    const searchInput = page.locator('input[aria-label="Search events"]');
    // Click outside search input
    await page.locator('header').click();
    await expect(searchInput).not.toBeFocused();

    // Press '/' key
    await page.keyboard.press('/');
    await expect(searchInput).toBeFocused();
  });

  test('should filter alerts by severity dropdown', async ({ page }) => {
    // Open advanced filters panel
    const filterToggleBtn = page.locator('.filter-toggle-btn');
    await filterToggleBtn.click();

    const filtersGrid = page.locator('.filters-grid');
    await expect(filtersGrid).toBeVisible();

    // Select Malicious severity
    const severitySelect = page.locator('select[aria-label="Filter by severity"]');
    await severitySelect.selectOption('malicious');

    // Verify active chip appears
    const chip = page.locator('.active-chips .chip');
    await expect(chip).toBeVisible();
    await expect(chip).toContainText('Severity: malicious');

    // All displayed rows should have malicious verdict badge
    const verdictBadges = page.locator('.verdict-badge');
    const count = await verdictBadges.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      await expect(verdictBadges.nth(i)).toHaveText('malicious');
    }
  });

  test('should filter alerts by workflow status dropdown', async ({ page }) => {
    const filterToggleBtn = page.locator('.filter-toggle-btn');
    await filterToggleBtn.click();

    const statusSelect = page.locator('[data-testid="filter-alert-status-select"]');
    await expect(statusSelect).toBeVisible();

    // Filter by 'acknowledged'
    await statusSelect.selectOption('acknowledged');

    // All rows should have Acknowledged status badge
    const statusBadges = page.locator('[data-testid^="status-badge-"]');
    const count = await statusBadges.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      await expect(statusBadges.nth(i)).toHaveClass(/status-acknowledged/);
    }
  });

  test('should reset all filters using Clear All button', async ({ page }) => {
    const searchInput = page.locator('input[aria-label="Search events"]');
    await searchInput.fill('password');

    const clearAllBtn = page.locator('.clear-all-btn');
    await expect(clearAllBtn).toBeVisible();
    await clearAllBtn.click();

    // Search input should be cleared
    await expect(searchInput).toHaveValue('');
    await expect(clearAllBtn).not.toBeVisible();
  });

  test('should save and delete a filter preset', async ({ page }) => {
    // Open filters
    await page.locator('.filter-toggle-btn').click();

    // Set a filter
    await page.locator('select[aria-label="Filter by severity"]').selectOption('malicious');

    // Click Save Preset
    const savePresetBtn = page.locator('.save-preset-btn');
    await savePresetBtn.click();

    // Enter preset name and save
    const presetNameInput = page.locator('input[placeholder="Preset name"]');
    await expect(presetNameInput).toBeVisible();
    await presetNameInput.fill('Critical Incidents');
    await page.locator('button[aria-label="Confirm preset name"]').click();

    // Preset chip should now appear
    const presetChip = page.locator('.preset-chip', { hasText: 'Critical Incidents' });
    await expect(presetChip).toBeVisible();

    // Delete preset
    const deleteBtn = presetChip.locator('button[aria-label="Delete preset"]');
    await deleteBtn.click();
    await expect(presetChip).not.toBeVisible();
  });

  test('should filter alert feed when clicking chart on main dashboard', async ({ page }) => {
    // Switch to Dashboard overview
    const dashNav = page.locator('nav button').filter({ hasText: 'Dashboard' });
    await dashNav.click();
    await expect(page.locator('.dashboard-grid')).toBeVisible();

    // Click a bar chart segment
    const barRectangle = page.locator('.recharts-bar-rectangle').first();
    await expect(barRectangle).toBeVisible();
    await barRectangle.click();

    // Should automatically switch to Alert Feed tab with filter active
    await expect(page.locator('.events-list')).toBeVisible();
    const chip = page.locator('.active-chips .chip');
    await expect(chip).toBeVisible();
    await expect(chip).toContainText('Severity: malicious');
  });
});
