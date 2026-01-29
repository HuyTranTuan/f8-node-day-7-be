const memoryStorage = {};

function createRateLimiter({ windowMs, maxRequests, message }) {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();

    if (!memoryStorage[ip] || now > memoryStorage[ip].resetTime) {
      memoryStorage[ip] = {
        count: 1,
        resetTime: now + windowMs,
      };
    }
    memoryStorage[ip].count += 1;

    if (memoryStorage[ip].count > maxRequests) return res.error(429, message);

    next();
  };
}

exports.apiRateLimiter = createRateLimiter({
  windowMs: 60000,
  maxRequests: 100,
  message: "Too many requests",
});
