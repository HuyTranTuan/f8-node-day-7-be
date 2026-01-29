const queueModel = require("../models/queue.model");

class QueueService {
    async push(job) {
        const { type, payload } = job;
        await queueModel.create(type, JSON.stringify(payload));
    }
}

module.exports = new QueueService();
