const emailService = require("../services/email.service");

async function sendChangePassword(payload) {
  await emailService.sendChangePassword(payload);
}

module.exports = sendChangePassword;
