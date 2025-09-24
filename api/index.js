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
import helmet from "helmet";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

//dewni
import inventoryRouter from "./routes/inventory.routs.js";

//shadini
import promotionRouter from "./routes/promotion.routes.js";

dotenv.config();
const MONGODB_URL =
  "mongodb+srv://pgmsadeep:1234@cluster0.phudmlq.mongodb.net/fashion?retryWrites=true&w=majority";

mongoose
  .connect(MONGODB_URL)
  .then(() => {
    console.log("Connected to Mongo DB successfully!!!");
  })
  .catch((err) => {
    console.log("Error connecting to Mongo");
  });

const app = express();

//
app.get("/", (req, res) => {
  res.json({ mssg: "Welcome to the app" });
});

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "*",
    methods: "GET,POST,PUT,DELETE,OPTIONS,PATCH",
    credentials: true,
  })
);
// Security headers via Helmet
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);
// Additional strict headers
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
  );
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

app.listen(3000, () => {
  console.log("Server listening on port 3000!!!");
});

// Secure upload constraints
const ALLOWED_MIME = ["image/jpeg", "image/png", "image/webp"];
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB per file

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const safeName = Date.now() + "-" + crypto.randomUUID() + path.extname(file.originalname).toLowerCase();
    cb(null, safeName);
  },
});

const fileFilter = (req, file, cb) => {
  if (!ALLOWED_MIME.includes(file.mimetype)) {
    return cb(new Error("Unsupported file type"));
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE_BYTES, files: 3 },
});

// Create 'uploads' directory if not exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Auth middleware import (lazy to avoid circular) & route hardening
import { verifyToken } from "./utils/verifyUser.js";

// Route to handle image uploads (authenticated & validated)
app.post("/api/upload", verifyToken, (req, res, next) => {
  upload.array("images", 3)(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        return res
          .status(400)
          .json({ success: false, message: `Upload error: ${err.message}` });
      }
      return res
        .status(400)
        .json({ success: false, message: err.message || "Upload failed" });
    }
    if (!req.files || req.files.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "No valid files uploaded" });
    }
    const filePaths = req.files.map((file) => `uploads/${file.filename}`);
    res.json({ success: true, filePaths });
  });
});

const __dirname = dirname(fileURLToPath(import.meta.url)); // Get directory name

// Serve uploads as static with caching & prevent execution via proper content-type sniffing protection
app.use(
  "/uploads",
  express.static(join(__dirname, "uploads"), {
    setHeaders: (res, filePath) => {
      res.setHeader("Cache-Control", "public, max-age=31536000");
      // Force download for anything not an allowed image (defense-in-depth)
      if (!/(\.png|\.jpg|\.jpeg|\.webp)$/i.test(filePath)) {
        res.setHeader("Content-Disposition", "attachment");
      }
    },
  })
);

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
