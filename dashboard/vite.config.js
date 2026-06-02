import { defineConfig } from 'vite';
import { viteStaticCopy } from 'vite-plugin-static-copy';

export default defineConfig({
  server: {
    port: 3000,
    host: '127.0.0.1',
    open: false
  },
  build: {
    outDir: 'dist'
  },
  plugins: [
    viteStaticCopy({
      targets: [
        {
          src: 'src/js',
          dest: 'src'
        }
      ]
    })
  ]
});
