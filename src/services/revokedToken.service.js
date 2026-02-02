const revokedTokenModel = require("../models/revokedToken.model");

class RevokedTokenService {
  async findOneExp() {
    const result = revokedTokenModel.findOneExp();
    return result;
  }

  deleteRevokedToken = async (revoked) => {
    const result = await revokedTokenModel.deleteRevokedToken(revoked);
    return result;
  };
}

module.exports = new RevokedTokenService();
