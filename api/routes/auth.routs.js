import express from "express";
import {
  google,
  signOut,
  signin,
  signup,
} from "../controllers/auth.controllers.js";
import { veryfyTocken } from "../utils/verifyUser.js";
import { generateCSRFToken } from "../utils/csrfProtection.js";
import rateLimit from "express-rate-limit";

const router = express.Router();

// Sign-in brute force mitigation
const signinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.SIGNIN_MAX_PER_WINDOW || "20", 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many login attempts. Please try again later.",
  },
});

router.post("/signup", signup);
router.post("/signin", signinLimiter, signin);
router.post("/google", google);
router.get("/signout", veryfyTocken, signOut);

export default router;
