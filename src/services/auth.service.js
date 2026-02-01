const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const { authSecret, verifyEmailSecret } = require("../config/jwt");
const {
  BCRYPT_SALT_ROUNDS,
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_DAYS,
} = require("../config/constants");

const userModel = require("../models/user.model");
const revokedTokenModel = require("../models/revokedToken.model");
const strings = require("../utils/strings");
const emailService = require("../services/email.service");
const queueService = require("../services/queue.service");

class AuthService {
  async register(username, email, password) {
    const hash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    try {
      const insertId = await userModel.create(username, email, hash);

      const newUser = {
        id: insertId,
        username,
        email,
      };

      const tokens = await this.responseWithTokens(newUser);

      queueService.push({
        type: "sendVerifyEmail",
        payload: newUser,
      });

      await emailService.sendVerifyEmail(newUser);

      return { user: newUser, token: tokens };
    } catch (error) {
      if (String(error).includes("Duplicate")) {
        return 409;
      } else {
        throw error;
      }
    }
  }

  async login(email, password) {
    const user = await userModel.findByEmail(email);
    const { id, username } = user;

    if (!user) return 404;

    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      return 401;
    }

    const thisUser = {
      id,
      username,
      email,
    };
    const tokens = await this.responseWithTokens(thisUser);
    return {
      user,
      token: tokens,
    };
  }

  async refreshToken(refreshToken) {
    const user = await userModel.findByRefreshToken(refreshToken);

    if (!user) {
      return null;
    }

    const tokens = await this.responseWithTokens(user);

    return tokens;
  }

  async verifyEmail(token) {
    const payload = jwt.verify(token, verifyEmailSecret);

    if (payload.exp < Date.now()) return null;

    const userId = payload.sub;
    const user = await userModel.findOne(userId);

    if (user.verified_at) return "Tài khoản đã được xác minh!";

    return await userModel.verifyEmail(userId);
  }

  async resendVerifyEmail(user) {
    if (user.verified_at) return null;

    await emailService.sendVerifyEmail(user);

    queueService.push({
      type: "sendVerifyEmail",
      payload: {
        id: user.id,
        email: user.email,
      },
    });

    return "Resend verify email thanh cong";
  }

  async changePassword(user, oldPassword, newPassword) {
    const userInDB = await userModel.findByEmail(user.email);

    if (!userInDB) return 404;

    const isValid = await bcrypt.compare(oldPassword, userInDB.password);
    const hash = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

    if (!isValid) {
      return 400;
    }

    try {
      const { id, username, email } = await userModel.updatePassword(
        userInDB.email,
        hash,
      );

      const userInfo = { id, username, email };

      queueService.push({
        type: "sendPasswordChangeEmail",
        payload: {
          id: user.id,
          email: user.email,
        },
      });

      return { user: userInfo };
    } catch (error) {
      throw error;
    }
  }

  responseWithTokens = async (user) => {
    const accessTokenTtlMs = ACCESS_TOKEN_TTL_SECONDS * 1000;
    const refreshTokenTtlMs = REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;

    const payload = {
      sub: user.id,
      exp: Date.now() + accessTokenTtlMs,
    };
    const accessToken = jwt.sign(payload, authSecret);
    const refreshToken = strings.createRandomString(32);
    const refreshTtl = new Date(Date.now() + refreshTokenTtlMs);

    await userModel.updateRefreshToken(user.id, refreshToken, refreshTtl);

    const response = {
      access_token: accessToken,
      access_token_ttl: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refreshToken,
      refresh_token_ttl: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60,
    };

    return response;
  };

  async addRevokedToken(token, userID) {
    const result = await revokedTokenModel.addRevokedToken(token, userID);
    return result;
  }

  async deleteRevokedToken(token) {
    const result = await revokedTokenModel.deleteRevokedToken(token);
    return result;
  }
}

module.exports = new AuthService();
