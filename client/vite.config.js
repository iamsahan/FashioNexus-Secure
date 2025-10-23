import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";

// https://vitejs.dev/config/
export default defineConfig({
  server: {
    // Add CORS configuration for the dev server
    cors: {
      origin: ["http://localhost:5173", "http://127.0.0.1:5173"],
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "X-CSRF-Token",
      ],
    },
    proxy: {
      "/api": {
        target: "http://localhost:3000",
        secure: false,
        changeOrigin: true,
        configure: (proxy, options) => {
          // Add security headers to development server
          proxy.on("proxyRes", (proxyRes, req, res) => {
            // Remove server information disclosure
            delete proxyRes.headers["server"];
            delete proxyRes.headers["x-powered-by"];

            // Add comprehensive security headers to API responses
            proxyRes.headers["X-Content-Type-Options"] = "nosniff";
            proxyRes.headers["X-Frame-Options"] = "SAMEORIGIN";
            proxyRes.headers["X-XSS-Protection"] = "1; mode=block";
            proxyRes.headers["Referrer-Policy"] =
              "strict-origin-when-cross-origin";
            proxyRes.headers["Content-Security-Policy"] =
              "default-src 'self'; script-src 'none'; style-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
            proxyRes.headers["Permissions-Policy"] =
              "camera=(), microphone=(), geolocation=(), payment=()";
            // Don't set COOP/COEP headers - they break OAuth popups
          });
        },
      },
    },
    // Security headers for development server - Relaxed for development
    headers: {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "SAMEORIGIN",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy":
        "camera=(), microphone=(), geolocation=(), payment=()",
      // Don't set COOP/COEP headers on main document to allow OAuth popups
      // These headers prevent popups from working properly
      // Relaxed CSP for development to allow React Fast Refresh and Google OAuth
      "Content-Security-Policy":
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' https://apis.google.com https://accounts.google.com; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: https: blob:; " +
        "connect-src 'self' ws: wss: http://localhost:* http://127.0.0.1:* https://accounts.google.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://*.firebaseio.com; " +
        "frame-src 'self' https://accounts.google.com https://*.firebaseapp.com; " +
        "media-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self';",
    },
  },
  build: {
    // Enable security optimizations
    minify: "terser",
    terserOptions: {
      compress: {
        drop_console: true, // Remove console logs in production
        drop_debugger: true,
      },
    },
    // Source map configuration for security
    sourcemap: false, // Disable source maps in production for security
    rollupOptions: {
      output: {
        // Obfuscate chunk names
        chunkFileNames: "assets/js/[name]-[hash].js",
        entryFileNames: "assets/js/[name]-[hash].js",
        assetFileNames: "assets/[ext]/[name]-[hash].[ext]",
      },
    },
  },
  preview: {
    // Security headers for preview server
    headers: {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "SAMEORIGIN",
      "X-XSS-Protection": "1; mode=block",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      // Don't set COOP/COEP to allow OAuth popups
    },
  },
  plugins: [react()],
});
