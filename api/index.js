import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import authRouter from "./routes/auth.routs.js";
import otpRouter from "./routes/otp.routs.js";
import discountRouter from "./routes/discount.route.js";
import orderRouter from "./routes/order.rout.js";
import userRouter from "./routes/user.route.js";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import cors from "cors";
import nodemailer from "nodemailer";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import helmet from "helmet";
import { veryfyTocken } from "./utils/verifyUser.js";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { authenticate } from "./middleware/auth.middleware.js";
import { getCSRFToken } from "./utils/csrfProtection.js";

//dewni
import inventoryRouter from "./routes/inventory.routs.js";

//shadini
import promotionRouter from "./routes/promotion.routes.js";

dotenv.config();
const MONGODB_URL = process.env.MONGO_URI; // Use the env variable

mongoose
  .connect(MONGODB_URL)
  .then(() => {
    console.log("Connected to Mongo DB successfully!!!");
  })
  .catch((err) => {
    console.log("Error connecting to Mongo");
  });

const app = express();

// Comprehensive security headers with helmet
app.use(
  helmet({
    // Content Security Policy with comprehensive directives
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "https://fonts.googleapis.com"], // Removed unsafe-inline
        scriptSrc: ["'self'"], // No unsafe directives
        imgSrc: ["'self'", "data:", "https:", "blob:"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "https://api.emailjs.com"],
        mediaSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"], // Prevents clickjacking
        upgradeInsecureRequests:
          process.env.NODE_ENV === "production" ? [] : null,
      },
    },
    // Strict Transport Security (HSTS)
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    // X-Frame-Options for clickjacking protection
    frameguard: {
      action: "deny",
    },
    // X-Content-Type-Options to prevent MIME sniffing
    noSniff: true,
    // X-XSS-Protection
    xssFilter: true,
    // Referrer Policy
    referrerPolicy: {
      policy: "strict-origin-when-cross-origin",
    },
    // Remove X-Powered-By header
    hidePoweredBy: true,
    // Cross Origin Embedder Policy
    crossOriginEmbedderPolicy: false, // Adjust based on your needs
    // DNS Prefetch Control
    dnsPrefetchControl: {
      allow: false,
    },
  })
);

//
app.get("/", (req, res) => {
  res.json({ mssg: "Welcome to the app" });
});

// Hide Express server information
app.disable("x-powered-by");

// Custom middleware to remove sensitive server headers and ensure security headers
app.use((req, res, next) => {
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");

  // Ensure critical security headers are always present
  res.set({
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=()",
  });

  // Add HSTS for HTTPS
  if (process.env.NODE_ENV === "production") {
    res.set(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload"
    );
  }

  next();
});

app.use(express.json());
app.use(cookieParser());

// Security middleware to block access to hidden files and sensitive paths
app.use((req, res, next) => {
  const path = req.path.toLowerCase();

  // Block access to hidden files and directories
  if (
    path.includes("/.") ||
    path.includes("\\.") ||
    path.endsWith(".env") ||
    path.endsWith(".git") ||
    path.includes("/.git/") ||
    path.includes("node_modules") ||
    path.endsWith(".log") ||
    path.endsWith(".bak") ||
    path.endsWith(".backup") ||
    path.endsWith(".tmp") ||
    path.includes("config.")
  ) {
    return res.status(404).json({ error: "File not found" });
  }

  next();
});
// Configure CORS with strict security settings
const allowedOrigins =
  process.env.NODE_ENV === "production"
    ? ["https://fashio.flowiix.com"]
    : ["http://localhost:5173", "http://127.0.0.1:5173"];

app.use(
  cors({
    origin: function (origin, callback) {
      // In development, be more permissive for testing tools like ZAP
      if (process.env.NODE_ENV !== "production") {
        // Allow localhost variations and testing tools
        if (
          !origin ||
          origin.startsWith("http://localhost") ||
          origin.startsWith("http://127.0.0.1") ||
          allowedOrigins.includes(origin)
        ) {
          return callback(null, true);
        }
      }

      // Production: strict origin checking
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS: Origin ${origin} not allowed`));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: [
      "Origin",
      "X-Requested-With",
      "Content-Type",
      "Accept",
      "Authorization",
      "X-CSRF-Token",
    ],
    credentials: true,
    optionsSuccessStatus: 200,
    maxAge: 86400, // 24 hours - cache preflight requests
  })
);

app.listen(3000, () => {
  console.log("Server listening on port 3000!!!");
});

// Allowed image MIME types
const ALLOWED_MIME = ["image/jpeg", "image/png", "image/webp", "image/jpg"];

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Destination folder outside of any dynamic execution context
  },
  filename: (req, file, cb) => {
    const safeExt = path.extname(file.originalname).toLowerCase();
    const randomName = crypto.randomBytes(16).toString("hex");
    cb(null, randomName + safeExt); // High entropy filename prevents enumeration
  },
});

const fileFilter = (req, file, cb) => {
  if (!ALLOWED_MIME.includes(file.mimetype)) {
    return cb(new Error("Invalid file type. Only JPG, PNG, WEBP allowed."));
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB per file
    files: 3, // align with UI expectation
  },
});

// Create 'uploads' directory if not exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Secure image upload endpoint (route-level security only)
app.post(
  "/api/upload",
  veryfyTocken,
  helmet({
    frameguard: { action: "deny" },
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        imgSrc: ["'self", "data:"],
        scriptSrc: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
  }),
  (req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  },
  (req, res, next) => {
    upload.array("images", 3)(req, res, (err) => {
      if (err) {
        if (err.message.includes("File too large")) {
          return res
            .status(400)
            .json({ success: false, message: "File size exceeds 2MB limit" });
        }
        return res
          .status(400)
          .json({ success: false, message: err.message || "Upload failed" });
      }
      next();
    });
  },
  (req, res) => {
    if (!req.files || req.files.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "No valid images uploaded" });
    }
    const filePaths = req.files.map((file) => `uploads/${file.filename}`);
    res.status(201).json({ success: true, filePaths });
  }
);

const __dirname = dirname(fileURLToPath(import.meta.url)); // Get directory name

app.use("/uploads", express.static(join(__dirname, "uploads")));

// CSRF token endpoint (must be authenticated)
app.get("/api/csrf-token", authenticate, getCSRFToken);

// API-specific security middleware
app.use("/api", (req, res, next) => {
  // Ensure anti-clickjacking headers are always present on API routes
  res.set({
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    Pragma: "no-cache",
    Expires: "0",
  });
  next();
});

// Enhanced security middleware specifically for API routes
app.use("/api", (req, res, next) => {
  // Ensure all API responses have comprehensive security headers
  res.set({
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
  });

  // Add HSTS for production
  if (process.env.NODE_ENV === "production") {
    res.set(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload"
    );
  }

  next();
});

app.use("/api/auth", authRouter);
app.use("/api/auth", otpRouter); // /sendotp & /verifyotp

app.use("/api/user", userRouter);
app.use("/api/discount", discountRouter);
app.use("/api/order", orderRouter);
// Use OTP routes

//dewni
app.use("/api/inventories", inventoryRouter);

// Use OTP routes
//promotion routes
app.use("/api/promotions", promotionRouter);

app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  return res.status(statusCode).json({
    success: false,
    statusCode,
    message,
  });
});

// Body Parser Middleware (keep after route registrations for potential body parsing needs)
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
