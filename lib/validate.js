module.exports = function(options, user, password, done) {
  var easyHash = require("easy-pbkdf2")(options.hashConfig);

  easyHash.verify(user.salt, user.hash, password, done);
};
