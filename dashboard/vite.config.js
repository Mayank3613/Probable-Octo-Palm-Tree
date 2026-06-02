import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 3000,
    host: '127.0.0.1',
    open: false
  },
  build: {
    outDir: 'dist'
  }
});
