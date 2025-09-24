import express from "express";
import rateLimit from "express-rate-limit";
import { sendOTP, verifyOTP } from "../controllers/otp.controller.js";

const router = express.Router();

// Rate limiters specific to OTP endpoints
const sendLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: parseInt(process.env.OTP_SEND_MAX_PER_WINDOW || "10", 10),
	standardHeaders: true,
	legacyHeaders: false,
	message: { success: false, message: "Too many OTP requests. Try later." },
});

const verifyLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: parseInt(process.env.OTP_VERIFY_MAX_PER_WINDOW || "50", 10),
	standardHeaders: true,
	legacyHeaders: false,
	message: { success: false, message: "Too many verification attempts." },
});

router.post("/sendotp", sendLimiter, sendOTP);
router.post("/verifyotp", verifyLimiter, verifyOTP);

export default router;
