module.exports = (options, user, password, done) => {
  if (!user || !user.hash || !user.salt) {
    return done(null, false);
  }

  const easyHash = require('easy-pbkdf2')(options.hashConfig);

  easyHash.verify(user.salt, user.hash, password, done);
};
