const pool = require("../config/database");

class User {
  async findAll(limit, offset) {
    const [rows] = await pool.query(
      `select username, email, role, is_verified from users limit ? offset ?;`,
      [limit, offset],
    );
    return rows;
  }

  async count() {
    const [rows] = await pool.query("select count(*) as count from users;");
    return rows[0].count;
  }

  async countNewUser() {
    const date = new Date();
    date.setDate(date.getDate() - 1);
    const prev = date.toISOString().slice(0, 10);

    const [rows] = await pool.query(
      "select count(*) as count from users where created_at between ? and ?;",
      [`${prev} 00:00:00`, `${prev} 23:59:59`],
    );
    return rows[0].count;
  }

  async findOne(id) {
    const [rows] = await pool.query(
      `select id, email, username, verified_at, created_at from users where id = ?;`,
      [id],
    );
    return rows[0];
  }

  async findByEmail(email) {
    const query = `select id, email, username, password, verified_at, created_at from users where email = ?;`;
    const [rows] = await pool.query(query, [email]);
    return rows[0];
  }

  async create(username, email, password) {
    const [{ insertId }] = await pool.query(
      `insert into users (username, email, password) values (?, ?, ?)`,
      [username, email, password],
    );
    return insertId;
  }

  async updateRefreshToken(id, token, ttl) {
    const query = `update users set refresh_token = ?, refresh_expires_at = ? where id = ?`;
    const [{ affectedRows }] = await pool.query(query, [token, ttl, id]);
    return affectedRows;
  }

  async verifyEmail(id) {
    const query = `update users set verified_at = now() where id = ?`;
    const [{ affectedRows }] = await pool.query(query, [id]);
    return affectedRows;
  }

  async resendVerifyEmail(id) {
    const query = `update users set verified_at = now() where id = ?`;
    const [{ affectedRows }] = await pool.query(query, [id]);
    return affectedRows;
  }

  async findByRefreshToken(token) {
    const query =
      "select * from users where refresh_token = ? and refresh_expires_at >= now();";
    const [rows] = await pool.query(query, [token]);
    return rows[0];
  }
}

module.exports = new User();
