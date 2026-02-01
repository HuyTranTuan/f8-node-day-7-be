module.exports = {
  // Server
  DEFAULT_PORT: 3000,

  // Pagination
  DEFAULT_PAGE_SIZE: 20,

  // Authentication
  BCRYPT_SALT_ROUNDS: 10,
  ACCESS_TOKEN_TTL_SECONDS: 3600,
  REFRESH_TOKEN_TTL_DAYS: 7,

  // Database
  DB_CONNECTION_LIMIT: 10,
  DB_MAX_IDLE: 10,
  DB_IDLE_TIMEOUT_MS: 60000,

  // Error Messages
  ERROR_MESSAGES: {
    UNAUTHORIZED: "Unauthorized",
    NOT_FOUND: "Not found",
    INVALID_JSON: "Invalid JSON format",
    DATABASE_ERROR: "Database operation failed",
    BAD_REQUESTED: "Bad requested! Info is not right!",
  },

  // HTTP Status Codes
  HTTP_STATUS: {
    OK: 200,
    CREATED: 201,
    BAD_REQUESTED: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    UNPROCESSABLE_ENTITY: 422,
    INTERNAL_SERVER_ERROR: 500,
  },

  QUEUE_STATUS: {
    PENDING: "pending",
    INPROGRESS: "inprogress",
    COMPLETED: "completed",
    FAILED: "failed",
  },
};
