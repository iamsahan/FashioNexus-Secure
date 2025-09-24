import mongoose from "mongoose";

// OTP Schema with TTL index on expiresAt
const otpSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, index: true },
    otpHash: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: true },
    attempts: { type: Number, default: 0 },
    blockedUntil: { type: Date },
    lastSentAt: { type: Date },
  },
  { timestamps: true }
);

// TTL index: document removed automatically once expiresAt < now
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const OtpToken = mongoose.model("OtpToken", otpSchema);

export default OtpToken;
