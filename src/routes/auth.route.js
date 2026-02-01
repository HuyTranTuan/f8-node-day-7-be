const express = require("express");
const router = express.Router();

const authController = require("../controllers/auth.controller");
const validateUser = require("../middlewares/validateUser");
const validateChangePassword = require("../middlewares/validateChangePassword");
const authRequired = require("../middlewares/authRequired");

router.post("/register", validateUser, authController.register);
router.post("/login", validateUser, authController.login);
router.post("/refresh-token", authController.refreshToken);
router.get("/me", authRequired, authController.getCurrentUser);
router.post("/verify-email", authController.verifyEmail);
router.post(
  "/resend-verify-email",
  authRequired,
  authController.resendVerifyEmail,
);
router.post(
  "/change-password",
  authRequired,
  validateChangePassword,
  authController.changePassword,
);
router.post("/logout", authRequired, authController.logout);

module.exports = router;
