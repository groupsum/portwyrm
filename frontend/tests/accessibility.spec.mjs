import AxeBuilder from '@axe-core/playwright';
import { expect, test } from 'playwright/test';

const tags = ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'];

async function assertNoAxeViolations(page, label) {
  const results = await new AxeBuilder({ page }).withTags(tags).analyze();
  expect(results.violations, `${label}: ${JSON.stringify(results.violations, null, 2)}`).toEqual([]);
}

test('a stale setup screen rechecks server state before authentication', async ({ page }) => {
  await page.setViewportSize({width: 390, height: 844});
  let setupChecks = 0;
  await page.route('**/api/setup', async route => {
    if (route.request().method() === 'GET' && setupChecks++ === 0) {
      await route.fulfill({json: {setup: false}});
      return;
    }
    await route.continue();
  });

  await page.goto('/ui/');
  await expect(page.getByRole('heading', { name: 'Create administrator' })).toBeVisible();
  await page.getByLabel('Email').fill('accessibility@example.test');
  await page.getByLabel('Password').fill('Accessibility-Test-Password-123!');
  await page.getByRole('button', { name: 'Create administrator' }).click();
  await expect(page.getByRole('heading', { name: 'Change the temporary password' })).toBeVisible();
});

test('login and authenticated operator surfaces pass automated WCAG checks', async ({ page }) => {
  await page.goto('/ui/');
  await expect(page.getByRole('heading', { name: /create administrator|welcome back/i })).toBeVisible();
  await assertNoAxeViolations(page, 'login');

  await page.getByLabel('Email').fill('accessibility@example.test');
  await page.getByLabel('Password').fill('Accessibility-Test-Password-123!');
  await page.getByRole('button', { name: /create administrator|sign in/i }).click();
  await expect(page.getByRole('heading', { name: 'Change the temporary password' })).toBeVisible();
  await assertNoAxeViolations(page, 'forced password change');
  await page.getByLabel('Current password').fill('Accessibility-Test-Password-123!');
  await page.getByLabel('New password', { exact: true }).fill('Accessibility-Private-Password-456!');
  await page.getByLabel('Confirm new password').fill('Accessibility-Private-Password-456!');
  await page.getByRole('button', { name: 'Change password' }).click();
  await expect(page.getByText('Password changed. Sign in with your new password.')).toBeVisible();
  await page.getByLabel('Password').fill('Accessibility-Private-Password-456!');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Proxy Workspace Overview' })).toBeVisible();

  for (const route of ['overview', 'hosts', 'certificates', 'access-lists', 'users', 'audit', 'settings']) {
    await page.evaluate(value => { window.location.hash = value; }, route);
    await page.waitForTimeout(150);
    await assertNoAxeViolations(page, route);
  }
});

test('login controls retain a keyboard-visible focus sequence', async ({ page }) => {
  await page.goto('/ui/');
  await expect(page.getByRole('heading', { name: /create administrator|welcome back/i })).toBeVisible();
  await page.getByLabel('Email').focus();
  await expect(page.getByLabel('Email')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('Password')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: /create administrator|sign in/i })).toBeFocused();
});
