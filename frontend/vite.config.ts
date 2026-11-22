import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Бэкенд (Spring Boot) по умолчанию на :8080. В dev-режиме /api проксируется туда,
// поэтому фронт ходит на относительные пути и одинаково работает в dev и в собранном jar.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
})
