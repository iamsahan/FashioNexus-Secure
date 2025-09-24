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

const router = express.Router();

// Public routes - anyone can view inventory
router.get("/all-offers", getInventorieswithOffers);
router.get("/search/get", getInventorySearch);
router.get("/:id", getInventory);

// Admin routes - only managers can manage inventory
router.post("/add", authenticate, requireManager, createInventory);
router.delete("/:id", authenticate, requireManager, deleteInventory);
router.patch("/:id", authenticate, requireManager, updateInventory);

export default router;
