var Hoek = require('hoek');
var Boom = require('boom');
var _ = require('lodash');
var fs = require('fs');
var path = require('path');
var Handlebars = require('handlebars');

var hash = require('./hash');
var validate = require('./validate');

var noop = function() {
  var error = "You must provide a method to get user data. See docs at https://github.com/firstandthird/hapi-auth-email";
  console.error(new Error(error));
  arguments[arguments.length-1](Boom.badImplementation(error));
};

var pluginDefaults = {
  schemeName: 'email',
  namespace: 'auth.', // Used for server methods
  getAccount: noop,
  saveAccount: noop, // Only used with default views
  useDefaultViews: true,
  redirectOnTry: true,
  redirectTo: '/login',
  loginPath: '/login',
  registerPath: '/register',
  resetPassPath: '/reset',
  successEndpont: '/',
  cookieName: 'hapi-auth-email', // Cookie options only used with default views
  cookieOptions: {
    ttl: null,
    path: '/',
    encoding: 'iron',
    password: 'somethingrandom'
  },
  hashConfig: {
    'DEFAULT_HASH_ITERATIONS': 128000,
    'SALT_SIZE': 64,
    'KEY_LENGTH': 256
  },
  loginForm: {
    name: 'App Name',
    description: ''
  },
  registerForm: {
    name: 'App Name',
    description: ''
  }
};

exports.register = function(server, pluginOptions, next) {

  var callFunc = function() {
    var params = Array.prototype.slice.call(arguments);
    var func = params.shift();
    var method = func;

    if (typeof func === 'string') {
      method = _.get(server.methods, func, noop);
    }

    method.apply(server, params);
  };

  pluginOptions = Hoek.applyToDefaults(pluginDefaults, pluginOptions);

  server.method(pluginOptions.namespace + 'generateHash', function(user, password, done) {
    hash(pluginOptions, user, password, done);
  });

  server.method(pluginOptions.namespace + 'validatePassword', function(user, password, done) {
    validate(pluginOptions, user, password, done);
  });

  server.auth.scheme(pluginOptions.schemeName, function(server, options) {
    return {
      authenticate: function(request, reply) {
        callFunc(pluginOptions.getAccount, request, function(err, user) {
          if (err) {
            server.log('hapi-auth-email', 'error', { message: 'Problem getting user', error: err });
            return reply(Boom.badImplementation('Problem getting user'));
          }

          if (!user || !user.email || !user.hash || user.salt) {

            if (pluginOptions.redirectOnTry === false && request.auth.mode === 'try') {
              return reply(Boom.unauthorized(null, pluginOptions.schemeName));
            }

            var uri = _.get(request.route.settings.plugins['hapi-auth-email'], 'redirectTo', pluginOptions.redirectTo);

            if (!uri) {
              return reply(Boom.unauthorized(null, pluginOptions.schemeName));
            }

            if (pluginOptions.appendNext) {
              if (uri.indexOf('?') !== -1) {
                uri += '&';
              } else {
                uri += '?';
              }

              uri += pluginOptions.appendNext + '=' + encodeURIComponent(request.url.path);
            }

            return reply('You are being redirected...', null, {}).redirect(uri);
          }

          return reply.continue({ credentials: user });
        });
      }
    };
  });

  // Below this sets up default views. Anything non view related should go above.
  if (!pluginOptions.useDefaultViews) {
    return next();
  }

  var loginHtml = fs.readFileSync(path.join(__dirname, '../views/login.html'), 'utf8');
  var loginView = Handlebars.compile(loginHtml);
  var registerHtml = fs.readFileSync(path.join(__dirname, '../views/register.html'), 'utf8');
  var registerView = Handlebars.compile(registerHtml);

  server.route({
    method: 'POST',
    path: pluginOptions.loginPath,
    config: {
      auth: false,
      handler: function(request, reply) {
        var valid = _.get(request.server.methods, pluginOptions.namespace + 'validatePassword');

        callFunc(pluginOptions.getAccount, request, function(err, user) {
          if (err) {
            return reply(Boom.badImplementation('Problem getting user'));
          }

          valid(user, request.payload.password, function(err, isValid) {
            if (err) {
              return reply(Boom.badImplementation('Problem verifying hash', err));
            }

            if (isValid) {
              return reply
                .redirect(request.payload.next || pluginOptions.successEndpont)
                .state(pluginOptions.cookieName, user, pluginOptions.cookieOptions);
            }

            return reply.redirect(request.url.path + '?error=1' + (request.payload.next ? '&next=' + request.payload.next : '') );
          });
        });
      }
    }
  });

  server.route({
    method: 'GET',
    path: pluginOptions.loginPath,
    config: {
      auth: false,
      handler: function(request, reply) {
        var out = loginView({
          name: pluginOptions.loginForm.name,
          description: pluginOptions.loginForm.description,
          css: pluginOptions.loginForm.css,
          error: request.query.error,
          endpoint: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.loginPath,
          register: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.registerPath,
          next: request.query.next ? encodeURI(request.query.next) : false
        });

        reply(null, out);
      }
    }
  });

  server.route({
    method: 'POST',
    path: pluginOptions.registerPath,
    config: {
      auth: false,
      handler: function(request, reply) {
        var valid = _.get(request.server.methods, pluginOptions.namespace + 'validatePassword');

        callFunc(pluginOptions.getAccount, request, function(err, user) {
          if (err) {
            return reply(Boom.badImplementation('Problem getting user'));
          }

          valid(user, request.payload.password, function(err, isValid) {
            if (err) {
              return reply(Boom.badImplementation('Problem verifying hash', err));
            }

            if (isValid) {
              return reply
                .redirect(request.payload.next || pluginOptions.successEndpont)
                .state(pluginOptions.cookieName, user, pluginOptions.cookieOptions);
            }

            return reply.redirect(request.url.path + '?error=1' + (request.payload.next ? '&next=' + request.payload.next : '') );
          });
        });
      }
    }
  });

  server.route({
    method: 'GET',
    path: pluginOptions.registerPath,
    config: {
      auth: false,
      handler: function(request, reply) {
        var out = registerView({
          name: pluginOptions.registerForm.name,
          description: pluginOptions.registerForm.description,
          css: pluginOptions.registerForm.css,
          error: request.query.error,
          endpoint: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.registerPath,
          login: _.get(request, 'route.realm.modifiers.route.prefix', '') + pluginOptions.loginPath,
          next: request.query.next ? encodeURI(request.query.next) : false
        });

        reply(null, out);
      }
    }
  });

  next();
};

exports.register.attributes = {
  pkg: require('../package.json')
};