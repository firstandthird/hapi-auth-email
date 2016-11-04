'use strict';
const code = require('code');   // assertion library
const Lab = require('lab');
const lab = exports.lab = Lab.script();
const Hapi = require('hapi');
const emailAuth = require('../');
const Iron = require('iron');

let server;

lab.experiment('hapi-auth-email', () => {
  lab.beforeEach((done) => {
    server = new Hapi.Server({
      debug: {
        log: ['hapi-auth-email', 'warning', 'info', 'error']
      }
    });
    server.connection({ host: 'localhost', port: 8000 });
    server.start(done);
  });

  lab.afterEach((done) => {
    server.stop(done);
  });

  lab.test('the email auth plugin can be registered with the server ', { timeout: 10000 }, (done) => {
    server.register({
      register: emailAuth,
      options: {},
      aParam: {
        hi: true
      }
    }, {
      routes: {
        prefix: '/auth'
      }
    }, (err) => {
      code.expect(err).to.equal(undefined);
      // should allow you to register it:
      server.auth.strategy('email', 'email', true);
      // should not allow you to register it twice:
      try {
        server.auth.strategy('email', 'email', true);
      } catch (e) {
        code.expect(e.message).to.include('strategy name already exists');
        return done();
      }
    });
  });

  lab.test('will redirect to /login page if no credentials ', { timeout: 10000 }, (done) => {
    server.register({
      register: emailAuth,
      options: {
        getAccount: (request, getAccountDone) => {
          getAccountDone(null, {});
        }
      }
    }, (err) => {
      code.expect(err).to.equal(undefined);
      server.auth.strategy('email', 'email', true);
      server.route({
        method: 'GET',
        path: '/',
        config: {
          handler: (request, reply) => {
            reply(request.auth);
          }
        }
      });
      const cookieOptions = {
        ttl: null,
        path: '/',
        encoding: 'iron',
        password: 'somethingrandom'
      };
      server.state('auth', cookieOptions);
      server.inject({
        url: '/',
        method: 'GET'
      }, (response) => {
        code.expect(response.statusCode).to.equal(302);
        code.expect(response.headers.location).to.equal('/login');
        done();
      });
    });
  });

  lab.test('processes a login POST and returns a cookie', (done) => {
    const password = 'somethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandom';
    // make a valid user hash:
    const hashConfig = {
      DEFAULT_HASH_ITERATIONS: 128000,
      SALT_SIZE: 64,
      KEY_LENGTH: 256
    };
    const user = {
      _id: '12345',
      email: 'email@example.com'
    };
    const hasher = require('../lib/hash.js');
    hasher(hashConfig, user, password, () => {
      const cookieOptions = {
        ttl: null,
        path: '/',
        encoding: 'iron',
        password
      };
      server.register({
        register: emailAuth,
        options: {
          cookieName: 'auth',
          cookieOptions,
          namespace: 'testLogin.',
          getAccount: (request, email, getAccountDone) => {
            if (request.payload.password !== password) {
              return getAccountDone(null, {
                email: 'email@example.com',
                salt: user.salt,
                hash: user.hash.replace('1', '2')
              });
            }
            getAccountDone(null, user);
          }
        }
      }, (err2) => {
        server.auth.strategy('email', 'email', true);
        server.state('session', cookieOptions);
        code.expect(err2).to.equal(undefined);
        server.inject({
          url: '/login',
          method: 'POST',
          payload: {
            email: 'email@email.com',
            password: 'badPassword'
          }
        }, (badResponse) => {
          code.expect(badResponse.statusCode).to.equal(302);
          code.expect(badResponse.headers.location).to.equal('/login?error=1');
          server.inject({
            url: '/login',
            method: 'POST',
            payload: {
              email: 'email@email.com',
              password
            }
          }, (response) => {
            code.expect(response.statusCode).to.equal(302);
            code.expect(typeof response.headers['set-cookie']).to.equal('object');
            code.expect(response.headers.location).to.equal('/');
            // see that the returned cookie was the right id
            Iron.unseal(response.headers['set-cookie'][0].split('auth=')[1].split(';')[0], password, Iron.defaults, (err, unsealed) => {
              if (err) {
                throw err;
              }
              code.expect(unsealed._id).to.equal('12345');
              done();
            });
          });
        });
      });
    });
  });

  lab.test('allows you to /register an account', { timeout: 10000 }, (done) => {
    const password = 'somethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandom';
    // make a valid user hash:
    const hashConfig = {
      DEFAULT_HASH_ITERATIONS: 128000,
      SALT_SIZE: 64,
      KEY_LENGTH: 256
    };
    const user = {
      _id: '123445',
      email: 'email@example.com'
    };
    const hasher = require('../lib/hash.js');
    hasher(hashConfig, user, password, () => {
      const cookieOptions = {
        ttl: null,
        path: '/',
        encoding: 'iron',
        password
      };
      server.register({
        register: emailAuth,
        options: {
          cookieName: 'auth',
          cookieOptions,
          namespace: 'testLogin.',
          getAccount: (request, email, getAccountDone) => {
            return getAccountDone(null, user);
          },
          saveAccount: (request, email, saveAccountDone) => {
            return saveAccountDone(null, user);
          }
        }
      }, (err) => {
        server.auth.strategy('email', 'email', true);
        server.state('auth', cookieOptions);
        code.expect(err).to.equal(undefined);
        server.inject({
          url: '/register',
          method: 'POST',
          payload: {
            email: user.email,
            password
          }
        }, (response) => {
          code.expect(response.statusCode).to.equal(302);
          code.expect(response.statusMessage).to.equal('Found');
          server.inject({
            url: '/login',
            method: 'POST',
            payload: {
              email: user.email,
              password
            }
          }, (response2) => {
            code.expect(response2.statusCode).to.equal(302);
            code.expect(response2.statusMessage).to.equal('Found');
            code.expect(typeof response2.headers['set-cookie']).to.equal('object');
            code.expect(response2.headers.location).to.equal('/');
            done();
          });
        });
      });
    });
  });

  lab.test('allows you to /reset an account', { timeout: 10000 }, (done) => {
    const password = 'somethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandomsomethingrandom';
    // make a valid user hash:
    const hashConfig = {
      DEFAULT_HASH_ITERATIONS: 128000,
      SALT_SIZE: 64,
      KEY_LENGTH: 256
    };
    const user = {
      _id: '123445',
      email: 'email@example.com'
    };
    const hasher = require('../lib/hash.js');
    hasher(hashConfig, user, password, () => {
      const cookieOptions = {
        ttl: null,
        path: '/',
        encoding: 'iron',
        password
      };
      server.register({
        register: emailAuth,
        options: {
          cookieName: 'auth',
          cookieOptions,
          namespace: 'testLogin.',
          getAccount: (request, email, getAccountDone) => {
            return getAccountDone(null, user);
          },
          saveAccount: (request, email, saveAccountDone) => {
            return saveAccountDone(null, user);
          }
        }
      }, (err) => {
        server.auth.strategy('email', 'email', true);
        server.state('auth', cookieOptions);
        server.inject({
          url: '/register',
          method: 'POST',
          payload: {
            email: user.email,
            password
          }
        }, () => {
          server.inject({
            url: '/reset',
            method: 'POST',
            payload: {
              email: user.email,
              next: '/nexty'
            }
          }, (response) => {
            code.expect(response.statusCode).to.equal(302);
            code.expect(response.headers.location).to.include('/nexty');
            code.expect(response.headers.location).to.include('reset=1');
            done();
          });
        });
      });
    });
  });
});
