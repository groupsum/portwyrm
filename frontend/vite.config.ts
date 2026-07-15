import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/ui/',
  plugins: [react(), tailwindcss()],
  build: { outDir: '../src/portwyrm/uix/static', emptyOutDir: true, sourcemap: false },
});
