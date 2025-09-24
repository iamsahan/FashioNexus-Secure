import Jwt from "jsonwebtoken";
import { errorHandler } from "./error.js";

export const veryfyTocken = (req, res, next) => {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.substring(7);
  } else if (req.cookies.access_token) {
    // legacy support if some flows still set it
    token = req.cookies.access_token;
  }
  if (!token) return next(errorHandler(401, "Unauthorized"));

  Jwt.verify(token, process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET, (err, user) => {
    if (err) return next(errorHandler(403, "Forbidden"));
    req.user = user;
    next();
  });
};
