const taskModel = require("../models/task.model");
const userModel = require("../models/user.model");
const paginationServices = require("./pagination.service");

class TaskService {
  model = taskModel;

  constructor() {
    paginationServices.apply(this);
  }

  getAllTasks = async (userID) => {
    this.userID = userID;
    const result = await this.pagination();
    return result;
  };

  getTaskById = async (id, userID) => {
    const result = await taskModel.findTask(id, userID);
    return result;
  };

  createTask = async (user, taskname, description) => {
    const result = await taskModel.createTask(user, taskname, description);
    return result;
  };

  updateTask = async (user, taskID, taskname, description) => {
    const result = await taskModel.updateTask(
      user,
      taskID,
      taskname,
      description,
    );
    return result;
  };

  toggleCompletedTask = async (user, taskID) => {
    const result = await taskModel.toggleCompletedTask(user, taskID);
    return result;
  };

  deleteTask = async (userID, id) => {
    const result = await taskModel.deleteTask(userID, id);
    return result;
  };
}

module.exports = new TaskService();
