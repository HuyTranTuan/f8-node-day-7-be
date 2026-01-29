require("dotenv").config();

const express = require("express");
const cors = require("cors");

const appRoutes = require("./src/routes");
const jsonHandler = require("./src/middlewares/jsonHandler");
const responseFormat = require("./src/middlewares/responseFormat");
const errorHandler = require("./src/middlewares/errorHandler");
const notFoundHandler = require("./src/middlewares/notFoundHandler");
const { apiRateLimiter } = require("./src/middlewares/rateLimiter");
const { DEFAULT_PORT } = require("./src/config/constants");

const app = express();
const port = process.env.PORT || DEFAULT_PORT;

const corsOptions = {
  origin: ["http://localhost:5173", "https://huytrantuan.github.io"],
  methods: "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 300,
};

app.use(cors(corsOptions));

app.use(jsonHandler);
app.use(responseFormat);
app.use(apiRateLimiter);

app.use("/api", appRoutes);
app.use(notFoundHandler);
app.use(errorHandler);

app.listen(port, "localhost", () => {
  console.log(`Server is listening at http://localhost:${port}`);
});
