const userModel = require("../models/user.model");
const paginationServices = require("./pagination.service");

class UserService {
  model = userModel;

  constructor() {
    paginationServices.apply(this);
  }

  async getUserByEmail(email) {
    const result = userModel.getUserByEmail(email);
    return result;
  }
}

module.exports = new UserService();
