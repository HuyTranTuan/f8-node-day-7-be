const { verifyEmailSecret } = require("../config/jwt");
const transporter = require("../config/nodemailer");
const jwtUtils = require("../utils/jwt");

class EmailService {
    async sendVerifyEmail(user) {
        const token = jwtUtils.sign(
            { sub: user.id, exp: Date.now() + 60 * 60 * 24 * 1000 },
            verifyEmailSecret
        );
        const info = await transporter.sendMail({
            from: '"F8" <your-email>',
            to: user.email,
            subject: "Xac thuc tai khoan",
            html: `<p><a href="http://localhost:5173?token=${token}">Click here</a>!</p>`,
        });
        return info;
    }

    async sendReportEmail(email, subject, usersCount) {
        const info = await transporter.sendMail({
            from: '"F8" <your-email>',
            to: email,
            subject,
            html: `
                <h1>Báo cáo hằng ngày</h1>
                <p>Người dùng đăng ký mới: ${usersCount}</p>
            `,
        });
        return info;
    }

    async sendBackupReport(email, subject, backupFile) {
        const info = await transporter.sendMail({
            from: '"F8" <your-email>',
            to: email,
            subject,
            html: `
                <h1>Backup DB thành công!</h1>
                <p>File đã backup: ${backupFile}</p>
            `,
        });
        return info;
    }
}

module.exports = new EmailService();
