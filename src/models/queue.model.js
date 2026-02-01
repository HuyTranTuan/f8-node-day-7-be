const pool = require("../config/database");

class Queue {
  async findAllPending() {
    const [rows] = await pool.query(
      `select * from queues where status = "pending";`,
    );
    return rows;
  }

  async findOnePending() {
    const [rows] = await pool.query(
      `select * from queues where status = "pending" limit 1;`,
    );
    console.log(rows[0]);
    return rows[0];
  }

  async create(type, payload) {
    const [{ insertId }] = await pool.query(
      `insert into queues (type, payload) values (?, ?)`,
      [type, payload],
    );
    return insertId;
  }

  async updateStatus(id, status) {
    const [{ affectedRows }] = await pool.query(
      `update queues set status = ? where id = ?`,
      [status, id],
    );
    return affectedRows;
  }
}

module.exports = new Queue();
