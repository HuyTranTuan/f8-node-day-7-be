const { JsonWebTokenError } = require("jsonwebtoken");
const { ERROR_MESSAGES, HTTP_STATUS } = require("../config/constants");

const errorHandler = (err, req, res, next) => {
  let status = HTTP_STATUS.INTERNAL_SERVER_ERROR;
  let errorMessage = err.message || String(err);

  if (err instanceof JsonWebTokenError) {
    errorMessage = ERROR_MESSAGES.UNAUTHORIZED;
    status = HTTP_STATUS.UNAUTHORIZED;
  }

  res.error(status, {
    message: errorMessage,
  });
};

module.exports = errorHandler;
