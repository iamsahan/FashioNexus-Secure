import jwt from "jsonwebtoken";
import { errorHandler } from "../utils/error.js";
import User from "../models/user.model.js";

// Simple authentication middleware
export const authenticate = async (req, res, next) => {
  try {
    // Get token from cookies
    const token = req.cookies.access_token;

    if (!token) {
      return next(errorHandler(401, "Authentication required"));
    }

    // Verify token (using the existing secret)
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "this_is_secret"
    );

    // Get user details from database
    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      return next(errorHandler(401, "User not found"));
    }

    // Set user info in request
    req.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      usertype: user.usertype,
      ismanager: user.ismanager,
    };

    next();
  } catch (error) {
    console.error("Authentication error:", error);

    if (error.name === "JsonWebTokenError") {
      return next(errorHandler(403, "Invalid token"));
    }

    if (error.name === "TokenExpiredError") {
      return next(errorHandler(401, "Token expired"));
    }

    return next(errorHandler(500, "Authentication failed"));
  }
};

// Role check middleware factory
export const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(errorHandler(401, "Authentication required"));
    }

    // Check if user has the required role
    if (role === "manager" && !req.user.ismanager) {
      return next(errorHandler(403, "Manager access required"));
    }

    if (role === "customer" && req.user.usertype !== "customer") {
      return next(errorHandler(403, "Customer access required"));
    }

    next();
  };
};

// Manager-only middleware
export const requireManager = (req, res, next) => {
  if (!req.user) {
    return next(errorHandler(401, "Authentication required"));
  }

  if (!req.user.ismanager) {
    return next(errorHandler(403, "Manager access required"));
  }

  next();
};

// Customer-only middleware
export const requireCustomer = (req, res, next) => {
  if (!req.user) {
    return next(errorHandler(401, "Authentication required"));
  }

  if (req.user.usertype !== "customer") {
    return next(errorHandler(403, "Customer access required"));
  }

  next();
};

// Self or manager access middleware
export const requireSelfOrManager = (req, res, next) => {
  if (!req.user) {
    return next(errorHandler(401, "Authentication required"));
  }

  const requestedUserId = req.params.userId || req.params.id;
  const isOwnResource = req.user.id.toString() === requestedUserId;
  const isManager = req.user.ismanager;

  if (!isOwnResource && !isManager) {
    return next(
      errorHandler(
        403,
        "Access denied - can only access own resources or manager required"
      )
    );
  }

  next();
};

// For backward compatibility with existing code
export const veryfyTocken = authenticate;
