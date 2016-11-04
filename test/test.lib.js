'use strict';
const code = require('code');   // assertion library
const Lab = require('lab');
const lab = exports.lab = Lab.script();
const hasher = require('../lib/hash.js');
const validate = require('../lib/validate.js');

lab.experiment('hapi-auth-email hashing', () => {
  const hashConfig = {
    DEFAULT_HASH_ITERATIONS: 128000,
    SALT_SIZE: 64,
    KEY_LENGTH: 256
  };
  const password = 'aslkdjfal;sdkjf;alskdjvqlj2490jasvlkaj;vlkj4ija;lsvjkq2490jvasdflk;vjq4jkasrvja;lwrkvja';
  const user = {
    email: 'email@email.com'
  };
  lab.test('can hash a password', (done) => {
    hasher(hashConfig, user, password, (err, result) => {
      code.expect(err).to.equal(null);
      code.expect(result.salt.length).to.equal(48);
      code.expect(result.email).to.equal(user.email);
      code.expect(typeof result.hash).to.equal('string');
      code.expect(result.hash.length).to.be.greaterThan(1);
      done();
    });
  });

  lab.test('can validate a user', (done) => {
    const options = { hashConfig };
    validate(options, {}, password, (err, isValid) => {
      code.expect(err).to.equal(null);
      code.expect(isValid).to.equal(false);
      validate(options, user, password, (err2, isValid2) => {
        code.expect(err2).to.equal(undefined);
        code.expect(isValid2).to.equal(true);
        done();
      });
    });
  });
});
