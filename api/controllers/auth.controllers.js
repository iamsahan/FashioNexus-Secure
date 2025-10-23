import User from "../models/user.model.js";
import bcryptjs from "bcryptjs";
import { errorHandler } from "../utils/error.js";
import jwt from "jsonwebtoken";
import admin from "../utils/firebaseAdmin.js";
import { validateEmail } from "../utils/security.js";
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
    // Validate email format
    const sanitizedEmail = validateEmail(email);
    if (!sanitizedEmail) {
      return next(errorHandler(400, "Valid email is required"));
    }

    const user = await User.findOne({ email: sanitizedEmail });
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
      .cookie("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      })
      .status(200)
      .json({
        user: rest,
        accessToken,
        expiresIn: process.env.ACCESS_TOKEN_EXP || "15m",
      });
  } catch (err) {
    next(err);
  }
};

export const google = async (req, res, next) => {
  try {
    const { idToken } = req.body;
    
    if (!idToken) {
      return next(errorHandler(400, "ID token is required"));
    }

    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture } = decodedToken;

    // Validate email format
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return next(errorHandler(400, "Valid email is required"));
    }

    // Sanitize email to prevent NoSQL injection
    const sanitizedEmail = email.toLowerCase().trim();

    let user = await User.findOne({ email: sanitizedEmail });
    
    if (user) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
      const { password: pass, ...rest } = user._doc;
      res
        .cookie("access_token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 24 * 60 * 60 * 1000, // 24 hours
        })
        .status(200)
        .json(rest);
    } else {
      const generatedPassword =
        Math.random().toString(36).slice(-8) +
        Math.random().toString(36).slice(-8);
      const newUser = await User.create({
        username:
          name.split(" ").join("").toLowerCase() +
          Math.random().toString(36).slice(-4),
        email: sanitizedEmail,
        password: bcryptjs.hashSync(generatedPassword, 10),
        avatar: picture,
        usertype: "customer",
      });
      const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);
      const { password: pass, ...rest } = newUser._doc;
      res
        .cookie("access_token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 24 * 60 * 60 * 1000, // 24 hours
        })
        .status(200)
        .json(rest);
    }
  } catch (error) {
    next(error);
  }
};

export const signOut = (req, res, next) => {
  try {
    res.clearCookie("access_token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    res.status(200).json("User has been signed out!");
  } catch (err) {
    next(err);
  }
};
