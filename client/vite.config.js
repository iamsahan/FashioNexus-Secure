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
        target: "http://16.171.225.212/",
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
            proxyRes.headers["X-Frame-Options"] = "DENY";
            proxyRes.headers["X-XSS-Protection"] = "1; mode=block";
            proxyRes.headers["Referrer-Policy"] =
              "strict-origin-when-cross-origin";
            proxyRes.headers["Content-Security-Policy"] =
              "default-src 'self'; script-src 'none'; style-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
            proxyRes.headers["Permissions-Policy"] =
              "camera=(), microphone=(), geolocation=(), payment=()";
          });
        },
      },
    },
    // Security headers for development server - More secure CSP with specific hashes
    headers: {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy":
        "camera=(), microphone=(), geolocation=(), payment=()",
      // Secure CSP for development with specific allowances for necessary libraries
      "Content-Security-Policy":
        "default-src 'self'; " +
        "script-src 'self' 'wasm-unsafe-eval'; " +
        "style-src 'self' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha256-hx0up+5msNNPOIf047hgFKR59NaAvp5txflkdef6WVE=' 'sha256-biLFinpqYMtWHmXfkA1BPeCY0/fNt46SAZ+BBk5YUog=' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: https: blob:; " +
        "connect-src 'self' ws: wss: http://localhost:3000 http://127.0.0.1:3000 http://16.171.225.212; " +
        "media-src 'self'; " +
        "object-src 'none'; " +
        "frame-src 'none'; " +
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
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    },
  },
  plugins: [react()],
});
