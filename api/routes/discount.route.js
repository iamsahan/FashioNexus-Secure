import express from "express";
import {
  createDiscount,
  deleteDiscounts,
  getDiscounts,
  updateDiscounts,
} from "../controllers/discount.controller.js";
import { authenticate, requireManager } from "../middleware/auth.middleware.js";

const router = express.Router();

// Public route - anyone can view discounts
router.get("/get", getDiscounts);

// Admin routes - only managers can manage discounts
router.post("/add", authenticate, requireManager, createDiscount);
router.put("/update/:id", authenticate, requireManager, updateDiscounts);
router.delete("/delete/:id", authenticate, requireManager, deleteDiscounts);

export default router;
