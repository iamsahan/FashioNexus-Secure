import csrf from "csrf";
import { errorHandler } from "./error.js";
import { tokenStore } from "../controllers/auth.controllers.js";

// Create CSRF instance
const tokens = new csrf();

// Generate CSRF token and associate with user session
export const generateCSRFToken = (req, res, next) => {
  try {
    // Get user ID from JWT token
    const userId = req.user?.id;
    if (!userId) {
      return next(errorHandler(401, "Authentication required for CSRF token"));
    }

    // Generate secret and token
    const secret = tokens.secretSync();
    const token = tokens.create(secret);

    // Store secret associated with user ID (convert ObjectId to string)
    tokenStore.set(userId.toString(), secret);

    // Set CSRF token in cookie with same security flags as access_token
    res.cookie("csrf_token", token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    next();
  } catch (error) {
    next(errorHandler(500, "Failed to generate CSRF token"));
  }
};

// Validate CSRF token for state-changing operations
export const validateCSRFToken = (req, res, next) => {
  try {
    // Skip CSRF validation for GET requests (read-only operations)
    if (req.method === "GET") {
      return next();
    }

    const userId = req.user?.id;
    if (!userId) {
      return next(errorHandler(401, "Authentication required"));
    }

    // Get token from header, body, or cookie
    const token = req.headers["x-csrf-token"] || req.body._csrf || req.cookies.csrf_token;
    if (!token) {
      return next(errorHandler(403, "CSRF token missing"));
    }

    // Get stored secret for this user (convert ObjectId to string)
    const secret = tokenStore.get(userId.toString());
    if (!secret) {
      return next(errorHandler(403, "CSRF secret not found"));
    }

    // Verify token
    const isValid = tokens.verify(secret, token);
    if (!isValid) {
      return next(errorHandler(403, "Invalid CSRF token"));
    }

    next();
  } catch (error) {
    next(errorHandler(500, "CSRF validation failed"));
  }
};

// Endpoint to get CSRF token for AJAX requests
export const getCSRFToken = (req, res, next) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return next(errorHandler(401, "Authentication required"));
    }

    // Generate or get existing token (convert ObjectId to string)
    const userIdStr = userId.toString();
    let secret = tokenStore.get(userIdStr);
    if (!secret) {
      secret = tokens.secretSync();
      tokenStore.set(userIdStr, secret);
    }

    const token = tokens.create(secret);

    res.json({ csrfToken: token });
  } catch (error) {
    next(errorHandler(500, "Failed to get CSRF token"));
  }
};

// Clean up expired tokens (call this periodically)
export const cleanupExpiredTokens = () => {
  // In production, implement proper cleanup based on user session expiry
  // For now, this is a placeholder
  console.log(
    "CSRF token cleanup - implement based on your session management"
  );
};
