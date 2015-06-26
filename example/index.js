var Hapi = require('hapi');
var _ = require('lodash');

var server = new Hapi.Server();
server.connection({ host: 'localhost', port: 8000 });

var users = [];

var cookieOptions = {
  ttl: null,
  path: '/',
  encoding: 'iron',
  password: 'somethingrandom'
};

server.register({
  register: require('../'),
  options: {
    getAccount: 'auth.getAccount',
    saveAccount: 'auth.saveAccount',
    redirectTo: '/auth/login',
    cookieOptions: cookieOptions,
    cookieName: 'auth'
  }
}, {
  routes: {
    prefix: '/auth'
  }
}, function(err) {
  server.auth.strategy('email', 'email', true);

  server.route({
    method: 'GET',
    path: '/',
    config: {
      handler: function(request, reply) {
        reply(request.auth);
      }
    }
  });

  server.state('auth', cookieOptions);

  server.method('auth.getAccount', function(request, email, done) {

    if (typeof email === 'function') {
      done = email;
      email = false;
    }

    if (!email) {
      if (typeof request.state.auth === 'object') {
        email = _.get(request, 'state.auth.email', '');
      } else {
        email = _.get(request, 'auth.credentials.email', '');
      }
    }

    done(null, _.find(users, { email: email }));
  });

  server.method('auth.saveAccount', function(request, user, done) {
    if (user.password) {
      console.log('Normally you\'d email the user here. New user password is ' + user.password);
      // you'd also not want to save the password in the user object.
      var index = _.indexOf(users, _.find(users, {email: user.email}));
      users.splice(index, 1, user);
    } else {
      users.push(user);
    }

    done(null, user);
  });

  server.start(function(err) {
    if (err) {
      return console.error(err);
    }

    console.log('Server started at:', server.info.uri);
  });
});
