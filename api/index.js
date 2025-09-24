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

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
     origin: "*",
    methods: "GET,POST,PUT,DELETE,OPTIONS,PATCH",
    credentials: true, 
  })
);

app.listen(3000, () => {
  console.log("Server listening on port 3000!!!");
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Destination folder
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Unique file name
  },
});

const upload = multer({ storage });

// Create 'uploads' directory if not exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Route to handle image uploads
app.post("/api/upload", upload.array("images", 3), (req, res) => {
  const filePaths = req.files.map((file) => `uploads/${file.filename}`);
  res.json({ filePaths });
});

const __dirname = dirname(fileURLToPath(import.meta.url)); // Get directory name

app.use("/uploads", express.static(join(__dirname, "uploads")));

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
