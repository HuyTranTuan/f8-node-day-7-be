const pool = require("../config/database");

class Task {
  async pagination(limit, offset, userID) {
    const [rows] = await pool.query(
      `select * from tasks where user_id = ? and deleted_at is null limit ? offset ?`,
      [userID, limit, offset],
    );
    return rows;
  }

  findAllTask = async (user) => {
    const [rows] = await pool.query(
      `select * from tasks where user_id = ? and deleted_at is null ;`,
      [user.id],
    );
    return rows;
  };

  findTask = async (id, userId) => {
    const [rows] = await pool.query(
      `select * from tasks where id = ? and user_id = ? and deleted_at is null ;`,
      [id, userId],
    );
    return rows[0];
  };

  createTask = async (user, taskname, description) => {
    const [{ insertId }] = await pool.query(
      `insert into tasks (user_id, taskname, description ) values (?, ?, ?)`,
      [user.id, taskname, description],
    );
    const task = this.findTask(insertId, user.id);
    return task;
  };

  updateTask = async (user, id, taskname, description) => {
    const task = await this.findTask(id, user.id);

    if (!task) return null;

    const now = new Date();

    await pool.query(
      `update tasks set taskname = ?, description = ?, updated_at = ? where user_id = ? and id = ?`,
      [taskname, description, now, user.id, id],
    );
    return await this.findTask(task.id, user.id);
  };

  toggleCompletedTask = async (user, taskID) => {
    const task = await this.findTask(taskID, user.id);

    const is_completed = task.is_completed === 0 ? 1 : 0;

    if (!task) return null;

    const now = new Date();

    await pool.query(
      `update tasks set is_completed = ?, updated_at = ? where user_id = ? and id = ?`,
      [is_completed, now, user.id, taskID],
    );
    return await this.findTask(task.id, user.id);
  };

  deleteTask = async (userID, id) => {
    const task = await this.findTask(id, userID);

    if (!task) return null;

    const now = new Date();

    await pool.query(
      `update tasks set deleted_at = ?, updated_at = ? where user_id = ? and id = ?`,
      [now, now, userID, id],
    );
    return "Deleted!";
  };

  async count() {
    const [rows] = await pool.query("select count(*) as count from tasks;");
    return rows[0].count;
  }
}

module.exports = new Task();
