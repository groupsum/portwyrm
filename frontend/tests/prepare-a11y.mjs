import { mkdirSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';

const frontendRoot = resolve(import.meta.dirname, '..');
const runtimeRoot = resolve(frontendRoot, '..', '.a11y-runtime');
rmSync(runtimeRoot, { recursive: true, force: true });
rmSync(resolve(frontendRoot, 'test-results'), { recursive: true, force: true });
mkdirSync(runtimeRoot, { recursive: true });
