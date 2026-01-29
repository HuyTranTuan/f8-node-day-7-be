const { ERROR_MESSAGES } = require("../config/constants");

const jsonHandler = (req, _, next) => {
  let body = "";
  req.on("data", (buffer) => {
    body += buffer.toString();
  });
  req.on("end", () => {
    if (body) {
      try {
        req.body = JSON.parse(body);
      } catch (error) {
        return next(new Error(ERROR_MESSAGES.INVALID_JSON));
      }
    }
    next();
  });
  req.on("error", (error) => {
    next(error);
  });
};

module.exports = jsonHandler;
