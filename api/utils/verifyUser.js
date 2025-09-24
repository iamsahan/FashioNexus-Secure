import jwt from "jsonwebtoken";
import { errorHandler } from "./error.js";

// Middleware to verify JWT from cookie (can be extended to accept Authorization header)
export const verifyToken = (req, res, next) => {
  const token = req.cookies?.access_token;
  if (!token) return next(errorHandler(401, "Unauthorized"));

  const secret = process.env.JWT_SECRET;
  if (!secret) return next(errorHandler(500, "Server misconfiguration"));

  jwt.verify(token, secret, (err, user) => {
    if (err) return next(errorHandler(403, "Forbidden"));
    req.user = user;
    next();
  });
};

// Backward compatibility export (if old name used elsewhere)
export const veryfyTocken = verifyToken;
