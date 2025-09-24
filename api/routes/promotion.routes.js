import express from "express";
import Promotion from "../models/promotion.model.js";
import {
  createPromotion,
  getPromotions,
  getPromotion,
  deletePromotion,
  updatePromotion,
  getPromotionSearch,
  getOfferbyItemId,
} from "../controllers/promotion.controllers.js";
import { authenticate, requireManager } from "../middleware/auth.middleware.js";

const router = express.Router();

// Public routes - anyone can view promotions
router.get("/", getPromotions);
router.get("/search/get", getPromotionSearch);
router.get("/offers/:itemId", getOfferbyItemId);
router.get("/:id", getPromotion);

// Admin routes - only managers can manage promotions
router.post("/", authenticate, requireManager, createPromotion);
router.delete("/:id", authenticate, requireManager, deletePromotion);
router.patch("/:id", authenticate, requireManager, updatePromotion);

export default router;
