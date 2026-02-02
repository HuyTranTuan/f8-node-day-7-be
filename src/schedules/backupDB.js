const { spawn, execSync } = require("node:child_process");
const fs = require("fs");
const emailService = require("../services/email.service");

function backupDB() {
  const outputFile = `./backup/day_7-${
    new Date().toISOString().split("T")[0]
  }.sql`;

  const outputStream = fs.createWriteStream(outputFile);

  const mysqldumpPath = process.env.SQL_DUMP;

  const mysqldump = spawn(mysqldumpPath, [
    `-u${process.env.DB_USER}`,
    `-p${process.env.DB_PASSWORD}`,
    `-P${process.env.DB_PORT}`,
    process.env.DB_NAME,
  ]);

  mysqldump.stdout.pipe(outputStream);

  mysqldump.on("error", (error) => {
    console.log(error);
    outputStream.end();
    console.error(`mysqldump error: ${error.message}`);
  });

  mysqldump.on("close", async (code) => {
    outputStream.end();
    console.log(`child process exited with code ${code}`);

    const rclonePath = process.env.R_CLONE;

    if (code === 0) {
      console.log(`Backup successfully! File: ${outputFile}`);
      // execSync(`${rclonePath} sync ./backup HUYBlogGDrive:backupdb`);
      // console.log(`Upload GDrive successfully!`);

      await emailService.sendBackupReport(
        process.env.BACKUP_EMAIL,
        "Backup thanh cong",
        outputFile,
      );
      console.log(`Send email report successfully!`);
    } else {
      fs.unlinkSync(outputFile);
    }
  });
}

module.exports = backupDB;
