import User from "../models/user.model.js";
import bcryptjs from "bcryptjs";
import { errorHandler } from "../utils/error.js";
import jwt from "jsonwebtoken";
import admin from "../utils/firebaseAdmin.js";
import {
  generateAccessToken,
  generateRefreshToken,
  hashRefreshId,
  verifyRefreshToken,
} from "../utils/tokens.js";

export const signup = async (req, res, next) => {
  const { username, email, password, ismanager, usertype } = req.body;
  const hashedPassword = bcryptjs.hashSync(password, 10);
  const newUser = new User({
    username,
    email,
    password: hashedPassword,
    usertype,
    ismanager,
  });
  try {
    await newUser.save();
    res.status(201).json("User created successfully!!!");
  } catch (error) {
    next(error);
  }
};

export const signin = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return next(errorHandler(404, "User not found"));
    const validPassword = bcryptjs.compareSync(password, user.password);
    if (!validPassword)
      return next(errorHandler(401, "Email or Password incorrect"));

    const accessToken = generateAccessToken(user._id);
    const { rid, token: refreshToken } = generateRefreshToken();
    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push({
      hash: hashRefreshId(rid),
      userAgent: req.headers["user-agent"],
      ip: req.ip,
    });
    await user.save();
    const { password: pass, refreshTokens, ...rest } = user._doc;
    res
      .cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/api/auth/refresh",
      })
      .status(200)
      .json({ user: rest, accessToken, expiresIn: process.env.ACCESS_TOKEN_EXP || "15m" });
  } catch (err) {
    next(err);
  }
};

export const google = async (req, res, next) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return next(errorHandler(400, "Missing idToken"));
    if (!admin.apps.length) {
      return next(errorHandler(500, "Firebase Admin not initialized"));
    }
    const decoded = await admin.auth().verifyIdToken(idToken);
    const email = decoded.email;
    const name = decoded.name || email.split("@")[0];
    const photo = decoded.picture;

    let user = await User.findOne({ email });
    if (!user) {
      const generatedPassword =
        Math.random().toString(36).slice(-8) +
        Math.random().toString(36).slice(-8);
      user = await User.create({
        username:
          name.split(" ").join("").toLowerCase() +
          Math.random().toString(36).slice(-4),
        email,
        password: bcryptjs.hashSync(generatedPassword, 10),
        avatar: photo,
        usertype: "customer",
      });
    }
    const accessToken = generateAccessToken(user._id);
    const { rid, token: refreshToken } = generateRefreshToken();
    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push({
      hash: hashRefreshId(rid),
      userAgent: req.headers["user-agent"],
      ip: req.ip,
    });
    await user.save();
    const { password: pass, refreshTokens, ...publicUser } = user._doc;
    res
      .cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/api/auth/refresh",
      })
      .status(200)
      .json({ user: publicUser, accessToken, expiresIn: process.env.ACCESS_TOKEN_EXP || "15m" });
  } catch (err) {
    next(err);
  }
};

export const refresh = async (req, res, next) => {
  try {
    const token = req.cookies.refresh_token;
    if (!token) return next(errorHandler(401, "No refresh token"));
    let payload;
    try {
      payload = verifyRefreshToken(token);
    } catch (e) {
      return next(errorHandler(403, "Invalid refresh token"));
    }

    // Search for user whose hashed rid matches
    const users = await User.find({ "refreshTokens.hash": { $exists: true } });
    let matchedUser = null;
    let matchedIndex = -1;
    for (const u of users) {
      for (let i = 0; i < (u.refreshTokens || []).length; i++) {
        const rt = u.refreshTokens[i];
        if (bcryptjs.compareSync(payload.rid, rt.hash)) {
          matchedUser = u;
          matchedIndex = i;
          break;
        }
      }
      if (matchedUser) break;
    }
    if (!matchedUser) return next(errorHandler(403, "Token revoked"));

    // Rotate
    matchedUser.refreshTokens.splice(matchedIndex, 1);
    const accessToken = generateAccessToken(matchedUser._id);
    const { rid, token: newRefresh } = generateRefreshToken();
    matchedUser.refreshTokens.push({
      hash: hashRefreshId(rid),
      userAgent: req.headers["user-agent"],
      ip: req.ip,
    });
    await matchedUser.save();
    res
      .cookie("refresh_token", newRefresh, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/api/auth/refresh",
      })
      .status(200)
      .json({ accessToken, expiresIn: process.env.ACCESS_TOKEN_EXP || "15m" });
  } catch (err) {
    next(err);
  }
};

export const signOut = async (req, res, next) => {
  try {
    // Optional: remove refresh token by device (not implemented: needs rid association)
    res.clearCookie("refresh_token", { path: "/api/auth/refresh" });
    res.status(200).json("User has been signed out!");
  } catch (err) {
    next(err);
  }
};
