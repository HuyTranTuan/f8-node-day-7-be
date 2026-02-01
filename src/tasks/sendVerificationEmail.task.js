const emailService = require("../services/email.service");

async function sendVerifyEmailTask(payload) {
  await emailService.sendVerifyEmail(payload);
}

module.exports = sendVerifyEmailTask;
