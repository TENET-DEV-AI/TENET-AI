import { defineConfig } from 'vite'

// The landing page is a static editorial page: plain HTML, one stylesheet and
// one small behaviour module. No framework runtime is needed to ship it.
export default defineConfig({
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
  },
})
