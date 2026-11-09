import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright E2E Configuration for TENET AI
 * Tests both the Landing Page (port 5173) and SOC Dashboard (port 5174).
 */
export default defineConfig({
  testDir: './tests/e2e',
  testIgnore: process.env.RUN_VISUAL === '1' ? [] : ['**/visual-regression.spec.ts'],
  timeout: 30 * 1000,
  expect: {
    timeout: 7000,
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.05,
      animations: 'disabled',
    },
  },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'playwright-report' }],
  ],
  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
      },
    },
  ],
  webServer: [
    {
      command: 'npm --prefix landing run dev',
      url: 'http://localhost:5173',
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
    },
    {
      command: 'npm --prefix dashboard run dev',
      url: 'http://localhost:5174',
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
    },
  ],
});
