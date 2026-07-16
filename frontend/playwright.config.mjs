import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'playwright/test';

const repositoryRoot = resolve(import.meta.dirname, '..');
const runtimeRoot = resolve(repositoryRoot, '.a11y-runtime');
mkdirSync(runtimeRoot, { recursive: true });

const browserPath = process.env.PORTWYRM_BROWSER_PATH
  || (process.platform === 'win32'
    ? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
    : undefined);

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  workers: 1,
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:18182',
    browserName: 'chromium',
    colorScheme: 'light',
    launchOptions: browserPath ? { executablePath: browserPath } : undefined,
  },
  webServer: {
    command: 'uv --no-cache run uvicorn portwyrm.api:create_app --factory --host 127.0.0.1 --port 18182',
    cwd: repositoryRoot,
    url: 'http://127.0.0.1:18182/health/ready',
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      ...process.env,
      PORTWYRM_DB_BACKEND: 'sqlite',
      PORTWYRM_DATA_ROOT: runtimeRoot,
      PORTWYRM_SQLITE_PATH: resolve(runtimeRoot, 'portwyrm.sqlite'),
      PORTWYRM_CERTIFICATE_ROOT: resolve(runtimeRoot, 'certificates'),
      PORTWYRM_INITIAL_ADMIN_EMAIL: 'accessibility@example.test',
      PORTWYRM_INITIAL_ADMIN_PASSWORD: 'Accessibility-Test-Password-123!',
      PORTWYRM_NGINX_RUNTIME: '0',
    },
  },
});
