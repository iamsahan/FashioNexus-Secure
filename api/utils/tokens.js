import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

export const generateAccessToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXP || '15m',
  });
};

export const generateRefreshToken = () => {
  const rid = crypto.randomBytes(32).toString('hex');
  const token = jwt.sign({ rid }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXP || '7d',
  });
  return { rid, token };
};

export const hashRefreshId = (rid) => bcrypt.hashSync(rid, 10);

export const verifyRefreshToken = (token) => jwt.verify(token, process.env.JWT_REFRESH_SECRET);
