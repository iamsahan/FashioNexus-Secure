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
      .cookie("access_token", token, {
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
    const user = await User.findOne({ email: req.body.email });
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
      user = await User.create({
        username:
          name.split(" ").join("").toLowerCase() +
          Math.random().toString(36).slice(-4),
        email,
        password: bcryptjs.hashSync(generatedPassword, 10),
        avatar: photo,
        usertype: "customer",
      });
      await newUser.save();
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
