import express from "express";
import {
  google,
  signOut,
  signin,
  signup,
} from "../controllers/auth.controllers.js";
import { veryfyTocken } from "../utils/verifyUser.js";
import { generateCSRFToken } from "../utils/csrfProtection.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/signin", signin);
router.post("/google", google);
router.get("/signout", veryfyTocken, signOut);

export default router;
