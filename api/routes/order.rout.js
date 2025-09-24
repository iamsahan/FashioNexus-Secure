import express from "express";
import {
  createOrder,
  deleteOrder,
  OrderByUser,
  updateOrder,
  updateStatus,
  AllOrder,
} from "../controllers/order.controller.js";
import { veryfyTocken } from "../utils/verifyUser.js";
import { validateCSRFToken } from "../utils/csrfProtection.js";

const router = express.Router();

// Protected routes with CSRF validation
router.post("/add", veryfyTocken, validateCSRFToken, createOrder);
router.get("/get/:userId", veryfyTocken, OrderByUser);
router.get("/get", veryfyTocken, AllOrder);
router.put("/update/:orderId", veryfyTocken, validateCSRFToken, updateOrder);
router.put("/status/:id", veryfyTocken, validateCSRFToken, updateStatus);
router.delete("/delete/:orderId", veryfyTocken, validateCSRFToken, deleteOrder);

export default router;
