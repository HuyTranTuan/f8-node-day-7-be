require("dotenv").config();
require("./src/config/database");

const { CronJob } = require("cron");

const dailyReport = require("./src/schedules/dailyReport");
const backupDB = require("./src/schedules/backupDB");

new CronJob("0 2 * * *", dailyReport, null, true);
new CronJob("0 3 * * * *", backupDB, null, true);
