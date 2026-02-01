require("dotenv").config();
require("./src/config/database");

const tasks = require("./src/tasks");
const constants = require("./src/config/constants");
const queueModel = require("./src/models/queue.model");
const sleep = require("./src/utils/sleep");

(async () => {
  while (true) {
    const pendingJob = await queueModel.findOnePending();
    if (pendingJob) {
      const type = pendingJob.type;
      const payload = JSON.parse(pendingJob.payload);

      try {
        console.log(`Job: "${type}" is processing...`);
        await queueModel.updateStatus(
          pendingJob.id,
          constants.QUEUE_STATUS.INPROGRESS,
        );

        const handler = tasks[type];
        console.log(handler);
        if (!handler) {
          throw new Error(`Khong co task xu ly cho: "${type}"`);
        }

        await handler(payload);

        await queueModel.updateStatus(
          pendingJob.id,
          constants.QUEUE_STATUS.COMPLETED,
        );

        console.log(`Job: "${type}" is processed`);
      } catch (error) {
        console.log(error);
        await queueModel.updateStatus(
          pendingJob.id,
          constants.QUEUE_STATUS.FAILED,
        );
      }
    }

    await sleep(2000);
  }
})();
