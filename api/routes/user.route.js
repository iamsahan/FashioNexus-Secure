import express from "express";
import {
  addUser,
  deleteUser,
  deleteUserByid,
  getAllUsers,
  getUser,
  getUserSearch,
  test,
  updateUser,
} from "../controllers/user.controllers.js";
import {
  authenticate,
  requireManager,
  requireSelfOrManager,
} from "../middleware/auth.middleware.js";
import { validateCSRFToken } from "../utils/csrfProtection.js";

const router = express.Router();

// Admin routes - only managers can access
router.get("/all-Users", authenticate, requireManager, getAllUsers); // GET request, no CSRF needed
router.delete(
  "/delete-user/:id",
  authenticate,
  requireManager,
  validateCSRFToken,
  deleteUserByid
);
router.get("/search", authenticate, requireManager, getUserSearch); // GET request, no CSRF needed
router.post("/add", authenticate, requireManager, validateCSRFToken, addUser);

// Public routes
router.get("/test", test);

// Self or manager access routes (with CSRF protection for state-changing operations)
router.post(
  "/update/:id",
  authenticate,
  requireSelfOrManager,
  validateCSRFToken,
  updateUser
);
router.delete(
  "/delete/:id",
  authenticate,
  requireSelfOrManager,
  validateCSRFToken,
  deleteUser
);
router.get("/:id", authenticate, requireSelfOrManager, getUser); // GET request, no CSRF needed

export default router;
