const authService = require("../services/auth.service");
const { ERROR_MESSAGES, HTTP_STATUS } = require("../config/constants");

const register = async (req, res) => {
  const { username, email, password } = req.body;
  const result = await authService.register(username, email, password);

  if (result === 409) res.error(HTTP_STATUS.CONFLICT, "Email đã tồn tại");

  const { user, token } = result;
  res.success(HTTP_STATUS.CREATED, user, token);
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const result = await authService.login(email, password);

  if (result === 404)
    return res.error(HTTP_STATUS.NOT_FOUND, ERROR_MESSAGES.NOT_FOUND);
  if (result === 401)
    return res.error(HTTP_STATUS.UNAUTHORIZED, ERROR_MESSAGES.UNAUTHORIZED);

  const { user, token } = result;
  const newHeader = `Bearer ${token.access_token}`;
  req.headers.authorization = newHeader;

  res.success(HTTP_STATUS.OK, user, token);
};

const getCurrentUser = async (req, res) => {
  res.success(HTTP_STATUS.OK, req.user);
};

const refreshToken = async (req, res) => {
  const authHeader = req.headers.authorization;
  const accessToken = authHeader.replace("Bearer ", "").trim();
  const refreshToken = req.body.refresh_token;
  const result = await authService.refreshToken(refreshToken, accessToken);

  if (!result)
    return res.error(HTTP_STATUS.NOT_FOUND, ERROR_MESSAGES.NOT_FOUND);

  if (result === 401)
    return res.error(HTTP_STATUS.UNAUTHORIZED, ERROR_MESSAGES.UNAUTHORIZED);

  const newHeader = `Bearer ${result.access_token}`;
  req.headers.authorization = newHeader;

  res.success(HTTP_STATUS.OK, result);
};

const verifyEmail = async (req, res) => {
  const token = req.body.token;
  const result = await authService.verifyEmail(token);
  if (!result)
    return res.error(
      HTTP_STATUS.FORBIDDEN,
      "Token da het han hoac khong hop le",
    );
  res.success("Verify email thanh cong");
};

const resendVerifyEmail = async (req, res) => {
  if (req.user.verified_at) {
    res.error(400, "Tai khoan da duoc xac minh!");
    return;
  }
  const { refreshToken } = req.body;
  const result = await authService.refreshToken(refreshToken);
  if (!result) return res.error(401, "Unauthoprized!");
  res.success(HTTP_STATUS.OK, result);
};

const logout = async (req, res) => {
  const authHeader = req.headers.authorization;
  const accessToken = authHeader.replace("Bearer ", "").trim();
  await authService.addRevokedToken(accessToken);
  res.success(HTTP_STATUS.OK, "Logged out!");
};

module.exports = {
  register,
  login,
  refreshToken,
  getCurrentUser,
  verifyEmail,
  resendVerifyEmail,
  logout,
};
