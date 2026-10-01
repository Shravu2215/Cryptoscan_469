'use strict';

const { ELEVATED_ROLES, canAccessRepo: hasOwnedRepoAccess } = require('./ownership');

function canAccessRepo(user, repo) {
  if (!user) return false;
  return hasOwnedRepoAccess(user.id, user.role, repo);
}

module.exports = { canAccessRepo, ELEVATED_ROLES };
