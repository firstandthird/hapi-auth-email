var Boom = require('boom');

module.exports = function(options, user, password, done) {
  var easyHash = require("easy-pbkdf2")(options.hashConfig);

  easyHash.secureHash(password, function(err, hash, salt) {
    if (err) {
      return done(err);
    }

    if (!hash || !salt) {
      return done(Boom.badImplementation('Error generating hash'));
    }

    user.salt = salt;
    user.hash = hash;

    done(null, user);
  });
};
