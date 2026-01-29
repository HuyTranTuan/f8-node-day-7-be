const validateUser = (req, res, next) => {
  const { email, password } = req.body;
  const errors = [];

  if (!email || email.trim().length < 10)
    errors.push("Email must have at least 10 characters!");

  if (
    !password ||
    !/^[a-z0-9-]+$/.test(password) ||
    password.trim().length < 10
  )
    errors.push(
      "Password must have at least 10 characters! (lowercase, numbers, dashes).",
    );

  if (errors.length > 0)
    return res.error(400, "Bad request! Missing email or password!", errors);

  next();
};

module.exports = validateUser;
