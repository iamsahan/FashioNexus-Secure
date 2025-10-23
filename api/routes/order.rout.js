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
import { validateCSRFToken } from "../utils/csrfProtection.js";

const router = express.Router();

// Customer routes - customers can create their own orders (with CSRF protection)
router.post("/add", authenticate,  createOrder);

// User-specific routes - users can view their own orders, managers can view any (GET requests don't need CSRF)
router.get("/get/:userId", authenticate, requireSelfOrManager, OrderByUser);

// Admin routes - only managers can access
router.get("/get", authenticate, requireManager, AllOrder); // GET request, no CSRF needed
router.put(
  "/update/:orderId",
  authenticate,
  requireManager,
  validateCSRFToken,
  updateOrder
);
router.put(
  "/status/:id",
  authenticate,
  requireManager,
  validateCSRFToken,
  updateStatus
);
router.delete(
  "/delete/:orderId",
  authenticate,
  requireManager,
  validateCSRFToken,
  deleteOrder
);

export default router;
