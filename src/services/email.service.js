const { verifyEmailSecret } = require("../config/jwt");
const transporter = require("../config/nodemailer");
const jwtUtils = require("../utils/jwt");

class EmailService {
  async sendVerifyEmail(user) {
    const token = jwtUtils.sign(
      { sub: user.id, exp: Date.now() + 60 * 60 * 2 * 1000 },
      verifyEmailSecret,
    );
    const info = await transporter.sendMail({
      from: '"F8" huydeptrai@gmail.com',
      to: user.email,
      subject: "Xac thuc tai khoan",
      html: `
        <p>
          <p>Nhấn vào liên kết này để xác minh tk của bạn</p>
          <a href="http://localhost:5173/auth/verify-email?token=${token}">Click here</a>!
        </p>
      `,
    });
    return info;
  }

  async sendChangePassword(user) {
    const info = await transporter.sendMail({
      from: '"F8" huydeptrai@gmail.com',
      to: user.email,
      subject: "Đổi mật khẩu",
      html: `
        <p>
          <h1>Đổi mật khẩu thành công!</h1>
          <p>Bạn đã đổi mật khẩu thành công, vui lòng đăng nhập lại vào hệ thống</p>
          <p>
            Nhấn vào liên kết để quay lại website <a href="http://localhost:5173/auth/login">Click here</a>!
          </p>
        </p>
      `,
    });
    return info;
  }

  async sendReportEmail(email, subject, usersCount) {
    const info = await transporter.sendMail({
      from: '"F8" huydeptrai@gmail.com',
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
      from: '"F8" huydeptrai@gmail.com',
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
