const express = require("express");
const router = express.Router();

const authController = require("../controllers/auth.controller");
const validateUser = require("../middlewares/user/validateUser");
const authRequired = require("../middlewares/authRequired");

router.post("/register", validateUser, authController.register);
router.post("/login", validateUser, authController.login);
router.post("/refresh-token", authRequired, authController.refreshToken);
router.get("/me", authRequired, authController.getCurrentUser);
router.post("/verify-email", authRequired, authController.verifyEmail);
router.post(
  "/resend-verify-email",
  authRequired,
  authController.resendVerifyEmail,
);
router.post("/logout", authRequired, authController.logout);

module.exports = router;
