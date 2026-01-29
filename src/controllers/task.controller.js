const taskServices = require("../services/task.service");
const { HTTP_STATUS, ERROR_MESSAGES } = require("../config/constants");

const getAllTasks = async (req, res) => {
  const result = await taskServices.getAllTasks(req.user.id);
  res.success(HTTP_STATUS.OK, result);
};

const getTaskByID = async (req, res) => {
  const taskID = req.params.id;
  const userID = req.user.id;
  const result = await taskServices.getTaskById(taskID, userID);
  if (!result) res.error(HTTP_STATUS.NOT_FOUND, ERROR_MESSAGES.NOT_FOUND);
  res.success(HTTP_STATUS.OK, result);
};

const createTask = async (req, res) => {
  const { user, body } = req;
  const { taskname, description } = body;
  const result = await taskServices.createTask(user, taskname, description);
  if (!result) res.error(HTTP_STATUS.NOT_FOUND, ERROR_MESSAGES.NOT_FOUND);
  res.success(HTTP_STATUS.OK, result);
};

const updateTask = async (req, res) => {
  const { user, body, params } = req;
  const taskID = params.id;
  const { taskname, description } = body;
  const result = await taskServices.updateTask(
    user,
    taskID,
    taskname,
    description,
  );
  if (!result) res.error(HTTP_STATUS.NOT_FOUND, ERROR_MESSAGES.NOT_FOUND);
  res.success(HTTP_STATUS.OK, result);
};

const toggleCompletedTask = async (req, res) => {
  const { user, params } = req;
  const taskID = params.id;
  const result = await taskServices.toggleCompletedTask(user, taskID);
  if (!result) res.error(HTTP_STATUS.NOT_FOUND, ERROR_MESSAGES.NOT_FOUND);
  res.success(HTTP_STATUS.OK, result);
};

const deleteTask = async (req, res) => {
  const { user, params } = req;
  const result = await taskServices.deleteTask(user.id, params.id);
  if (!result) res.error(HTTP_STATUS.NOT_FOUND, ERROR_MESSAGES.NOT_FOUND);
  res.success(HTTP_STATUS.OK, result);
};

module.exports = {
  getAllTasks,
  getTaskByID,
  createTask,
  updateTask,
  toggleCompletedTask,
  deleteTask,
};
