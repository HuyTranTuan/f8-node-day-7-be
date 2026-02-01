const pool = require("../config/database");

class RevokedToken {
  async findRevokedToken(access_token) {
    const [rows] = await pool.query(
      `select * from revoked_tokens where token = ?;`,
      [access_token],
    );
    return rows[0];
  }

  async addRevokedToken(access_token, userID) {
    const [rows] = await pool.query(
      `insert into revoked_tokens (token, user_id) values (?, ?);`,
      [access_token, userID],
    );
    return rows[0];
  }

  async deleteRevokedToken(access_token) {
    const [rows] = await pool.query(
      `delete from revoked_tokens where token = ?;`,
      [access_token],
    );
    return rows[0];
  }
}

module.exports = new RevokedToken();
