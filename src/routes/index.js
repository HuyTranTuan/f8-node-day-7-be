const express = require("express");
const router = express.Router();

const authRoute = require("./auth.route");
const taskRoute = require("./tasks.route");

router.use("/auth", authRoute);
router.use("/tasks", taskRoute);

module.exports = router;
