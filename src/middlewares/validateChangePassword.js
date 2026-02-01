const validateChangePassword = (req, res, next) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;
  const errors = [];

  if (
    !oldPassword ||
    !/^[a-z0-9-]+$/.test(oldPassword) ||
    oldPassword.trim().length < 10
  )
    errors.push(
      "Old password must have at least 10 characters! (lowercase, numbers, dashes).",
    );

  if (
    !newPassword ||
    !/^[a-z0-9-]+$/.test(newPassword) ||
    newPassword.trim().length < 10
  )
    errors.push(
      "New password must have at least 10 characters! (lowercase, numbers, dashes).",
    );

  if (
    !confirmPassword ||
    !/^[a-z0-9-]+$/.test(confirmPassword) ||
    confirmPassword.trim().length < 10
  )
    errors.push(
      "Confirm password must have at least 10 characters! (lowercase, numbers, dashes).",
    );

  if (oldPassword === newPassword)
    errors.push("New passowrd must different from old password!");

  if (newPassword !== confirmPassword)
    errors.push("Confirm passowrd must match new password!");

  if (errors.length > 0)
    return res.error(
      400,
      "Bad request! Missing old password or new password!",
      errors,
    );

  next();
};

module.exports = validateChangePassword;
