// Input validation middleware for request validation

import { errorHandler } from "../utils/error.js";
import {
  validateEmail,
  isValidObjectId,
  sanitizeSearchQuery,
} from "../utils/security.js";

/**
 * Validate email in request body
 */
export const validateEmailMiddleware = (req, res, next) => {
  const { email } = req.body;

  if (email) {
    const sanitizedEmail = validateEmail(email);
    if (!sanitizedEmail) {
      return next(errorHandler(400, "Valid email is required"));
    }
    req.body.email = sanitizedEmail;
  }

  next();
};

/**
 * Validate ObjectId parameters
 */
export const validateObjectIdParam = (paramName) => {
  return (req, res, next) => {
    const id = req.params[paramName];
    if (id && !isValidObjectId(id)) {
      return next(errorHandler(400, `Invalid ${paramName} format`));
    }
    next();
  };
};

/**
 * Sanitize search queries
 */
export const sanitizeSearchMiddleware = (req, res, next) => {
  if (req.query.searchTerm) {
    req.query.searchTerm = sanitizeSearchQuery(req.query.searchTerm);
  }
  next();
};

/**
 * Rate limiting middleware for authentication endpoints
 */
export const authRateLimit = (req, res, next) => {
  // Simple in-memory rate limiting (use Redis in production)
  const ip = req.ip;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 5;

  if (!global.authAttempts) {
    global.authAttempts = new Map();
  }

  const attempts = global.authAttempts.get(ip) || [];
  const recentAttempts = attempts.filter((time) => now - time < windowMs);

  if (recentAttempts.length >= maxAttempts) {
    return next(
      errorHandler(
        429,
        "Too many authentication attempts. Please try again later."
      )
    );
  }

  recentAttempts.push(now);
  global.authAttempts.set(ip, recentAttempts);

  next();
};

/**
 * Validate file upload parameters
 */
export const validateFileUpload = (req, res, next) => {
  if (req.files && req.files.length > 0) {
    const allowedTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
    const maxSize = 2 * 1024 * 1024; // 2MB

    for (const file of req.files) {
      if (!allowedTypes.includes(file.mimetype)) {
        return next(
          errorHandler(400, "Invalid file type. Only images are allowed.")
        );
      }
      if (file.size > maxSize) {
        return next(
          errorHandler(400, "File size too large. Maximum 2MB allowed.")
        );
      }
    }
  }
  next();
};
