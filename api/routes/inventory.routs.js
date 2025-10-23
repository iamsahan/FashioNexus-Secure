import express from "express";
import {
  getInventories,
  getInventory,
  createInventory,
  deleteInventory,
  updateInventory,
  getInventorySearch,
  getInventorieswithOffers,
} from "../controllers/inventory.controller.js";
import { authenticate, requireManager } from "../middleware/auth.middleware.js";
import { validateCSRFToken } from "../utils/csrfProtection.js";

const router = express.Router();

// Public routes - anyone can view inventory
router.get("/", getInventories);
router.get("/all-offers", getInventorieswithOffers);
router.get("/search/get", getInventorySearch);
router.get("/:id", getInventory);

// Admin routes - only managers can manage inventory (with CSRF protection)
router.post(
  "/add",
  authenticate,
  requireManager,
  validateCSRFToken,
  createInventory
);
router.delete(
  "/:id",
  authenticate,
  requireManager,
  validateCSRFToken,
  deleteInventory
);
router.patch(
  "/:id",
  authenticate,
  requireManager,
  validateCSRFToken,
  updateInventory
);

export default router;
