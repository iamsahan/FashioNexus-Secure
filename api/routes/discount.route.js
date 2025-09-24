import express from "express";
import {
  createDiscount,
  deleteDiscounts,
  getDiscounts,
  updateDiscounts,
} from "../controllers/discount.controller.js";
import { veryfyTocken } from "../utils/verifyUser.js";
import { validateCSRFToken } from "../utils/csrfProtection.js";

const router = express.Router();

// Protected routes with CSRF validation
router.post("/add", veryfyTocken, validateCSRFToken, createDiscount);
router.get("/get", getDiscounts); // Public read endpoint
router.put("/update/:id", veryfyTocken, validateCSRFToken, updateDiscounts);
router.delete("/delete/:id", veryfyTocken, validateCSRFToken, deleteDiscounts);

export default router;
