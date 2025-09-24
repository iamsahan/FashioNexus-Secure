import express from "express";
import {
  createDiscount,
  deleteDiscounts,
  getDiscounts,
  updateDiscounts,
} from "../controllers/discount.controller.js";
import { authenticate, requireManager } from "../middleware/auth.middleware.js";
import { validateCSRFToken } from "../utils/csrfProtection.js";

const router = express.Router();

// Public route - anyone can view discounts
router.get("/get", getDiscounts);

// Admin routes - only managers can manage discounts (with CSRF protection)
router.post(
  "/add",
  authenticate,
  requireManager,
  validateCSRFToken,
  createDiscount
);
router.put(
  "/update/:id",
  authenticate,
  requireManager,
  validateCSRFToken,
  updateDiscounts
);
router.delete(
  "/delete/:id",
  authenticate,
  requireManager,
  validateCSRFToken,
  deleteDiscounts
);

export default router;
