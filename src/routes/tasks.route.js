const express = require("express");
const router = express.Router();

const taskController = require("../controllers/task.controller");
const authRequired = require("../middlewares/authRequired");

router.get("/", authRequired, taskController.getAllTasks);
router.get("/:id", authRequired, taskController.getTaskByID);
router.post("/", authRequired, taskController.createTask);
router.patch("/:id", authRequired, taskController.updateTask);
router.put("/:id", authRequired, taskController.updateTask);
router.patch(
  "/:id/toggle-completed",
  authRequired,
  taskController.toggleCompletedTask,
);
router.put(
  "/:id/toggle-completed",
  authRequired,
  taskController.toggleCompletedTask,
);
router.delete("/:id", authRequired, taskController.deleteTask);

module.exports = router;
