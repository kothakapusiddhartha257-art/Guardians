import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('error', (err, req, res) => {
            if (!res.headersSent && res.writeHead) {
              res.writeHead(502, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ detail: 'Backend offline, standalone frontend active' }));
            }
          });
        }
      },
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
        configure: (proxy) => {
          proxy.on('error', () => {});
        }
      }
    }
  }
})
