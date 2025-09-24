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
import helmet from "helmet"; // used only on the upload endpoint (not global)
import { veryfyTocken } from "./utils/verifyUser.js";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { veryfyTocken } from "./utils/verifyUser.js";
import { getCSRFToken } from "./utils/csrfProtection.js";

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

app.use(express.json());
app.use(cookieParser());
// Configure CORS with restricted origins for production
const allowedOrigins =
  process.env.NODE_ENV === "production"
    ? ["https://fashio.flowiix.com"]
    : ["http://localhost:5173", "http://127.0.0.1:5173"];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: "GET,POST,PUT,DELETE,OPTIONS,PATCH",
    credentials: true,
    optionsSuccessStatus: 200,
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
        imgSrc: ["'self" , "data:"],
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
app.get("/api/csrf-token", veryfyTocken, getCSRFToken);

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
