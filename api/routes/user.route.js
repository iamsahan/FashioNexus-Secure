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

const router = express.Router();

// Admin routes - only managers can access
router.get("/all-Users", authenticate, requireManager, getAllUsers);
router.delete("/delete-user/:id", authenticate, requireManager, deleteUserByid);
router.get("/search", authenticate, requireManager, getUserSearch);
router.post("/add", authenticate, requireManager, addUser);

// Public routes
router.get("/test", test);

// Self or manager access routes
router.post("/update/:id", authenticate, requireSelfOrManager, updateUser);
router.delete("/delete/:id", authenticate, requireSelfOrManager, deleteUser);
router.get("/:id", authenticate, requireSelfOrManager, getUser);

export default router;
