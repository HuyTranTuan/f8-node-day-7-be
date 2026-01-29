const { HTTP_STATUS } = require("../config/constants");

const responseFormat = (_, res, next) => {
  res.success = (status = HTTP_STATUS.OK, data, passProps = {}) => {
    res.status(status).json({
      status: "success",
      data,
      ...passProps,
    });
  };

  res.paginate = ({ rows, pagination }) => {
    res.success(HTTP_STATUS.OK, rows, { pagination });
  };

  res.error = (
    status = HTTP_STATUS.INTERNAL_SERVER_ERROR,
    message,
    error = null,
  ) => {
    res.status(status).json({
      status: "error",
      error,
      message,
    });
  };

  next();
};

module.exports = responseFormat;
