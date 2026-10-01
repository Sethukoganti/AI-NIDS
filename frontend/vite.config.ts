import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

/**
 * The dev server proxies /api to the FastAPI backend so the browser only ever
 * talks to one origin (no CORS juggling, and it works behind the sandbox
 * preview host as well).
 */
const BACKEND = process.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000'

// When the app is viewed through a proxied preview host, HMR must be told
// which port/protocol to use. Locally nothing is set and Vite behaves normally.
const hmrClientPort = process.env.VITE_HMR_CLIENT_PORT

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    hmr: hmrClientPort
      ? { clientPort: Number(hmrClientPort), protocol: process.env.VITE_HMR_PROTOCOL === 'ws' ? 'ws' : 'wss' }
      : undefined,
    proxy: {
      '/api': {
        target: BACKEND,
        changeOrigin: true,
        ws: true,
        // Server-Sent Events must not be buffered
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes) => {
            if (proxyRes.headers['content-type']?.includes('text/event-stream')) {
              proxyRes.headers['cache-control'] = 'no-cache'
            }
          })
        },
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
    allowedHosts: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
})
