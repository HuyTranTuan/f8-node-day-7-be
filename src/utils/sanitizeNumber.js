const sanitizeNumber = (value, defaultValue) => {
  if (value && value.trim() !== "" && !isNaN(value)) {
    const parsed = parseInt(value, 10);
    return parsed > 0 ? parsed : defaultValue;
  }
  return defaultValue;
};

module.exports = sanitizeNumber;
