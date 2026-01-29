const { spawn, execSync } = require("node:child_process");
const fs = require("fs");
const emailService = require("../services/email.service");

function backupDB() {
    const outputFile = `./backup/blog_dev-${
        new Date().toISOString().split("T")[0]
    }.sql`;

    const outputStream = fs.createWriteStream(outputFile);

    const mysqldump = spawn("mysqldump", [
        // Thay từ env vào
        `-uadmin`,
        `-padmin`,
        "-P3307",
        "blog_dev",
    ]);

    mysqldump.stdout.pipe(outputStream);

    mysqldump.on("error", (error) => {
        outputStream.end();
        console.error(`mysqldump error: ${error.message}`);
    });

    mysqldump.on("close", async (code) => {
        outputStream.end();
        console.log(`child process exited with code ${code}`);

        if (code === 0) {
            console.log(`Backup successfully! File: ${outputFile}`);
            execSync(`rclone sync ./backup F8BlogGDrive:backupdb`);
            console.log(`Upload GDrive successfully!`);

            await emailService.sendBackupReport(
                "<your-email>",
                "Backup thanh cong",
                outputFile
            );
            console.log(`Send email report successfully!`);
        } else {
            fs.unlinkSync(outputFile);
        }
    });
}

module.exports = backupDB;
