const userModel = require("../models/user.model");
const emailService = require("../services/email.service");

async function dailyReport() {
  const usersCount = await userModel.countNewUser();

  const date = new Date();
  date.setDate(date.getDate() - 1);
  const prev = date.toISOString().slice(0, 10);

  await emailService.sendReportEmail(
    process.env.BACKUP_EMAIL,
    `Daily report ${prev}`,
    usersCount,
  );
  console.log("Send daily report successfully");
}

module.exports = dailyReport;
