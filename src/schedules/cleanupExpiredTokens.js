const revokedTokenService = require("../services/revokedToken.service");

async function cleanupExpiredTokens() {
  const revoked = await revokedTokenService.findOneExp();
  if (!revoked) console.log("Done!");

  await revokedTokenService.deleteRevokedToken(revoked);
  console.log("Deleted!");
}

module.exports = cleanupExpiredTokens;
