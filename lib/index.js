const Hoek = require('hoek');
const Boom = require('boom');
const _ = require('lodash');
const fs = require('fs');
const path = require('path');
const Handlebars = require('handlebars');
const hash = require('./hash');
const validate = require('./validate');

const noop = function(...args) {
  const error = 'You must provide a method to get user data. See docs at https://github.com/firstandthird/hapi-auth-email';
  console.error(new Error(error));
  const done = _.last(args);
  done(Boom.badImplementation(error));
};

const tplNoop = function(request, reply, data, output, done) {
  done(null, output);
};

const pluginDefaults = {
  schemeName: 'email',
  namespace: 'auth.', // Used for server methods
  getAccount: noop,
  saveAccount: noop, // Only used with default views
  useDefaultViews: true,
  useDefaultPosts: true,
  redirectOnTry: true,
  redirectTo: '/login',
  loginPath: '/login',
  loginPathTemplate: tplNoop,
  registerPath: '/register',
  registerPathTemplate: tplNoop,
  resetPassPath: '/reset',
  resetPassPathTemplate: tplNoop,
  loginPostPath: '/login',
  registerPostPath: '/register',
  resetPassPostPath: '/reset',
  successEndpont: '/',
  cookieName: 'hapi-auth-email', // Cookie options only used with default views
  flashCookie: 'hapi-auth-email-flash',
  cookieOptions: {
    ttl: 365 * 24 * 60 * 60 * 1000, // one year
    path: '/',
    encoding: 'iron',
    password: 'this-must-be-a-very-long-string-now',
    isSecure: false
  },
  hashConfig: {
    DEFAULT_HASH_ITERATIONS: 128000,
    SALT_SIZE: 64,
    KEY_LENGTH: 256
  },
  loginForm: {
    name: 'App Name',
    description: ''
  },
  registerForm: {
    name: 'App Name',
    description: ''
  },
  resetForm: {
    name: 'App Name',
    description: ''
  },
  loginRedirectFilter: (request, user, uri, done) => {
    done(null, uri);
  }
};

exports.register = (server, pluginOptions, next) => {
  const callFunc = function(...args) {
    let serverMethod = _.first(args);
    serverMethod = typeof serverMethod === 'string' ? _.get(server.methods, serverMethod, noop) : serverMethod;
    serverMethod.apply(server, _.tail(args));
  };

  pluginOptions = Hoek.applyToDefaults(pluginDefaults, pluginOptions);

  server.method(`${pluginOptions.namespace}generateHash`, (user, password, done) => {
    hash(pluginOptions, user, password, done);
  });

  server.method(`${pluginOptions.namespace}validatePassword`, (user, password, done) => {
    validate(pluginOptions, user, password, done);
  });

  server.state(pluginOptions.cookieName, pluginOptions.cookieOptions);
  server.state(pluginOptions.flashCookie, pluginOptions.cookieOptions);

  server.auth.scheme(pluginOptions.schemeName, (server2) => { // eslint-disable-line arrow-body-style
    return {
      authenticate: (request, reply) => {
        callFunc(pluginOptions.getAccount, request, (err, user) => {
          if (err) {
            server2.log('hapi-auth-email', 'error', { message: 'Problem getting user', error: err });
            return reply(Boom.badImplementation('Problem getting user'));
          }

          if (!user || !user.email) {
            if (pluginOptions.redirectOnTry === false && request.auth.mode === 'try') {
              return reply(Boom.unauthorized(null, pluginOptions.schemeName));
            }

            let uri = _.get(request.route.settings.plugins['hapi-auth-email'], 'redirectTo', pluginOptions.redirectTo);

            if (!uri) {
              return reply(Boom.unauthorized(null, pluginOptions.schemeName));
            }

            if (pluginOptions.appendNext) {
              if (uri.indexOf('?') !== -1) {
                uri += '&';
              } else {
                uri += '?';
              }

              uri += `${pluginOptions.appendNext}=${encodeURIComponent(request.url.path)}`;
            }

            return reply(null, 'You are being redirected...', {}).redirect(uri);
          }

          return reply.continue({ credentials: user });
        });
      }
    };
  });

  if (pluginOptions.useDefaultPosts) {
    server.route({
      method: 'POST',
      path: pluginOptions.loginPostPath,
      config: {
        auth: false,
        handler: (request, reply) => {
          const valid = _.get(request.server.methods, `${pluginOptions.namespace}validatePassword`);
          const useJSON = (request.query.type && request.query.type === 'json');

          callFunc(pluginOptions.getAccount, request, request.payload.email, (err, user) => {
            if (err) {
              return reply(Boom.badImplementation('Problem getting user'));
            }
            valid(user, request.payload.password, (err2, isValid) => {
              if (err2) {
                return reply(Boom.badImplementation('Problem verifying hash', err2));
              }

              if (isValid) {
                if (useJSON) {
                  return reply({ success: true }).state(pluginOptions.cookieName, user);
                }

                return callFunc(pluginOptions.loginRedirectFilter, user, request, request.payload.next || pluginOptions.successEndpont, (error, uri) => {
                  if (error) {
                    return reply(Boom.badImplementation('Problem redirecting'));
                  }

                  return reply
                    .redirect(uri)
                    .state(pluginOptions.cookieName, user);
                });
              }

              if (useJSON) {
                return reply(Boom.conflict('Incorrect credentials'));
              }

              return reply
                .redirect(`${request.url.path}?error=1${(request.payload.next ? `&next=${request.payload.next}` : '')}`)
                .state(pluginOptions.flashCookie, request.payload);
            });
          });
        }
      }
    });

    server.route({
      method: 'POST',
      path: pluginOptions.registerPostPath,
      config: {
        auth: false,
        handler: (request, reply) => {
          const user = {
            email: request.payload.email
          };
          const useJSON = request.query.type;

          const hash2 = _.get(request.server.methods, `${pluginOptions.namespace}generateHash`);
          hash2(user, request.payload.password, (err, hashed) => {
            if (err) {
              if (useJSON) {
                return reply(err);
              }

              return reply
                .redirect(`${request.url.path}?error=1${(request.payload.next ? `&next=${request.payload.next}` : '')}`)
                .state(pluginOptions.flashCookie, request.payload);
            }
            callFunc(pluginOptions.saveAccount, request, hashed, (err2, savedUser) => {
              if (err2) {
                if (useJSON) {
                  return reply(err2);
                }

                return reply
                  .redirect(`${request.url.path}?error=2${(request.payload.next ? `&next=${request.payload.next}` : '')}`)
                  .state(pluginOptions.flashCookie, request.payload);
              }
              if (useJSON) {
                return reply({ success: true }).state(pluginOptions.cookieName, savedUser);
              }
              return reply
                .redirect(request.payload.next || pluginOptions.successEndpont)
                .state(pluginOptions.cookieName, savedUser);
            });
          });
        }
      }
    });

    server.route({
      method: 'POST',
      path: pluginOptions.resetPassPostPath,
      config: {
        auth: false,
        handler: (request, reply) => {
          const user = {
            email: request.payload.email,
            password: Math.random().toString(36).slice(2)
          };
          const resetHash = _.get(request.server.methods, `${pluginOptions.namespace}generateHash`);
          resetHash(user, user.password, (err, hashed) => {
            if (err) {
              return reply
                .redirect(`${request.url.path}?error=2${(request.payload.next ? `&next=${request.payload.next}` : '')}`)
                .state(pluginOptions.flashCookie, request.payload);
            }

            hashed.password = user.password;
            callFunc(pluginOptions.saveAccount, request, hashed, (err2) => {
              if (err2) {
                return reply
                  .redirect(`${request.url.path}?error=1${(request.payload.next ? `&next=${request.payload.next}` : '')}`)
                  .state(pluginOptions.flashCookie, request.payload);
              }

              return reply.redirect(`${_.get(request, 'route.realm.modifiers.route.prefix', '')}${pluginOptions.loginPath}?reset=1${(request.payload.next ? `&next=${request.payload.next}` : '')}`);
            });
          });
        }
      }
    });
  }

  // Below this sets up default views. Anything non view related should go above.
  if (!pluginOptions.useDefaultViews) {
    return next();
  }

  const loginHtml = fs.readFileSync(path.join(__dirname, '../views/login.html'), 'utf8');
  const loginView = Handlebars.compile(loginHtml);
  const registerHtml = fs.readFileSync(path.join(__dirname, '../views/register.html'), 'utf8');
  const registerView = Handlebars.compile(registerHtml);
  const resetHtml = fs.readFileSync(path.join(__dirname, '../views/reset.html'), 'utf8');
  const resetView = Handlebars.compile(resetHtml);

  server.route({
    method: 'GET',
    path: pluginOptions.loginPath,
    config: {
      handler: (request, reply) => {
        const context = {
          error: request.query.error,
          endpoint: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.loginPath,
          register: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.registerPath,
          reset: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.resetPassPath,
          passReset: request.query.reset,
          next: request.query.next ? encodeURI(request.query.next) : false
        };

        if (request.auth.credentials) {
          return callFunc(pluginOptions.loginRedirectFilter, request.auth.credentials, request, context.next || pluginOptions.successEndpont, (error, uri) => {
            if (error) {
              return reply(Boom.badImplementation('Problem redirecting'));
            }

            return reply
              .redirect(uri);
          });
        }

        const data = Object.assign({}, pluginOptions.loginForm, context);
        const out = loginView(data);

        callFunc(pluginOptions.loginPathTemplate, request, reply, data, out, (err, html) => {
          if (err) {
            return reply(err);
          }

          reply(null, html);
        });
      }
    }
  });

  server.route({
    method: 'GET',
    path: pluginOptions.registerPath,
    config: {
      auth: false,
      handler: (request, reply) => {
        const context = {
          error: request.query.error,
          endpoint: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.registerPath,
          login: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.loginPath,
          next: request.query.next ? encodeURI(request.query.next) : false
        };
        const data = Object.assign({}, pluginOptions.registerForm, context);
        const out = registerView(data);

        callFunc(pluginOptions.registerPathTemplate, request, reply, data, out, (err, html) => {
          if (err) {
            return reply(err);
          }

          reply(null, html);
        });
      }
    }
  });

  server.route({
    method: 'GET',
    path: pluginOptions.resetPassPath,
    config: {
      auth: false,
      handler: (request, reply) => {
        const context = {
          error: request.query.error,
          endpoint: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.resetPassPath,
          login: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.loginPath,
          next: request.query.next ? encodeURI(request.query.next) : false
        };
        const data = Object.assign({}, pluginOptions.resetForm, context);
        const out = resetView(data);

        callFunc(pluginOptions.resetPassPathTemplate, request, reply, data, out, (err, html) => {
          if (err) {
            return reply(err);
          }

          reply(null, html);
        });
      }
    }
  });

  next();
};

exports.register.attributes = {
  pkg: require('../package.json')
};
