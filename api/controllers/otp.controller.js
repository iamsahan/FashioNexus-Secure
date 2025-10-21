import nodemailer from "nodemailer";
import bcryptjs from "bcryptjs";
import crypto from "crypto";
import OtpToken from "../models/otp.model.js";

// Configurable defaults (can be overridden via environment variables)
const OTP_LENGTH = parseInt(process.env.OTP_LENGTH || "6", 10);
const OTP_EXP_MIN = parseInt(process.env.OTP_EXP_MIN || "5", 10); // minutes
const OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS || "5", 10);
const OTP_BLOCK_MIN = parseInt(process.env.OTP_BLOCK_MIN || "15", 10); // minutes blocked after exceeding attempts
const OTP_RESEND_COOLDOWN_SEC = parseInt(
  process.env.OTP_RESEND_COOLDOWN_SEC || "60",
  10
);

// Lazy transporter creation to avoid failing app start if env vars missing
const getTransporter = () => {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    throw new Error(
      "Email credentials not configured. Set GMAIL_USER and GMAIL_PASS in .env"
    );
  }
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });
};

// Secure OTP generation using crypto.randomInt
const generateNumericOTP = () => {
  const max = 10 ** OTP_LENGTH;
  return crypto.randomInt(0, max).toString().padStart(OTP_LENGTH, "0");
};

// Basic email format validation
const isValidEmail = (email) => /.+@.+\..+/.test(email);

// Send OTP Controller
export const sendOTP = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !isValidEmail(email)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid email address" });
    }

    const lowerEmail = email.toLowerCase();
    const existing = await OtpToken.findOne({ email: lowerEmail });

    const now = new Date();
    if (existing) {
      // Check if currently blocked
      if (existing.blockedUntil && existing.blockedUntil > now) {
        return res.status(429).json({
          success: false,
          message: "Too many attempts. Please try again later.",
        });
      }
      // Cooldown to avoid spamming email resend
      if (
        existing.lastSentAt &&
        now - existing.lastSentAt < OTP_RESEND_COOLDOWN_SEC * 1000
      ) {
        return res.status(429).json({
          success: false,
          message: `OTP already sent. Please wait a few seconds before requesting again`,
        });
      }
    }

    const otp = generateNumericOTP();
    const otpHash = bcryptjs.hashSync(otp, 10);
    const expiresAt = new Date(Date.now() + OTP_EXP_MIN * 60 * 1000);

    if (existing) {
      existing.otpHash = otpHash;
      existing.expiresAt = expiresAt;
      existing.attempts = 0; // reset attempts for new OTP
      existing.lastSentAt = now;
      await existing.save();
    } else {
      await OtpToken.create({
        email: lowerEmail,
        otpHash,
        expiresAt,
        attempts: 0,
        lastSentAt: now,
      });
    }

    const transporter = getTransporter();

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: lowerEmail,
      subject: "Your Verification Code",
      html: `
      <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; background:#f5f5f5; }
            .container { max-width:600px;margin:0 auto;padding:20px;background:#fff;border-radius:10px; }
            .otp { padding:12px 18px; display:inline-block; background:#111827;color:#fff;font-size:22px;font-weight:700;letter-spacing:4px;border-radius:8px; }
            p { font-size:14px; color:#111; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Email Verification</h2>
            <p>Use the OTP below to verify your email. It will expire in ${OTP_EXP_MIN} minutes.</p>
            <div class="otp">${otp}</div>
            <p>If you did not request this, you can safely ignore this email.</p>
          </div>
        </body>
      </html>`,
    };

    await transporter.sendMail(mailOptions);
    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
    });
  } catch (err) {
    console.error("sendOTP error", err);
    return res
      .status(500)
      .json({ success: false, message: "Failed to send OTP" });
  }
};

// Verify OTP Controller
export const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res
        .status(400)
        .json({ success: false, message: "Email and OTP required" });
    }
    const lowerEmail = email.toLowerCase();
    const record = await OtpToken.findOne({ email: lowerEmail });
    const now = new Date();

    if (!record) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP" });
    }

    if (record.blockedUntil && record.blockedUntil > now) {
      return res.status(429).json({
        success: false,
        message: "Too many attempts. Please try again later.",
      });
    }

    if (record.expiresAt < now) {
      await record.deleteOne();
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP" });
    }

    const match = bcryptjs.compareSync(otp, record.otpHash);
    if (!match) {
      record.attempts += 1;
      if (record.attempts >= OTP_MAX_ATTEMPTS) {
        record.blockedUntil = new Date(Date.now() + OTP_BLOCK_MIN * 60 * 1000);
      }
      await record.save();
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP" });
    }

    // Success: remove record to prevent reuse
    await record.deleteOne();
    return res
      .status(200)
      .json({ success: true, message: "OTP verified successfully" });
  } catch (err) {
    console.error("verifyOTP error", err);
    return res
      .status(500)
      .json({ success: false, message: "OTP verification failed" });
  }
};
