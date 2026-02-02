const pool = require("../config/database");

class RevokedToken {
  async findOneExp() {
    const [rows] = await pool.query(
      `select * from revoked_tokens where expires_at < now() limit 1;`,
    );
    return rows[0];
  }

  async findRevokedToken(access_token) {
    const [rows] = await pool.query(
      `select * from revoked_tokens where token = ?;`,
      [access_token],
    );
    return rows[0];
  }

  async addRevokedToken(access_token, exp, userID) {
    const [rows] = await pool.query(
      `insert into revoked_tokens (token, expires_at, user_id) values (?, ?, ?);`,
      [access_token, exp, userID],
    );
    return rows[0];
  }

  async deleteRevokedToken(revoked) {
    if (revoked) {
      const [rows] = await pool.query(
        `delete from revoked_tokens where token = ? and expires_at < now();`,
        [revoked.token],
      );
      return rows[0];
    }
  }
}

module.exports = new RevokedToken();
