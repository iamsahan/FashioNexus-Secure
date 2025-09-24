import express from "express";
import {
  createOrder,
  deleteOrder,
  OrderByUser,
  updateOrder,
  updateStatus,
  AllOrder,
} from "../controllers/order.controller.js";
import {
  authenticate,
  requireManager,
  requireSelfOrManager,
} from "../middleware/auth.middleware.js";

const router = express.Router();

// Customer routes - customers can create their own orders
router.post("/add", authenticate, createOrder);

// User-specific routes - users can view their own orders, managers can view any
router.get("/get/:userId", authenticate, requireSelfOrManager, OrderByUser);

// Admin routes - only managers can access
router.get("/get", authenticate, requireManager, AllOrder);
router.put("/update/:orderId", authenticate, requireManager, updateOrder);
router.put("/status/:id", authenticate, requireManager, updateStatus);
router.delete("/delete/:orderId", authenticate, requireManager, deleteOrder);

export default router;
