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
  server.auth.strategy('email', 'email', true, {
    loginForm: {
      name: 'hapi-auth-email example',
      description: 'Accounts are only stored in memory'
    }
  });

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

  server.method('auth.getAccount', function(request, done) {
    var email = '';

    if (typeof request.state.auth === 'object') {
      email = _.get(request, 'state.auth.email', '');
    } else {
      email = _.get(request, 'auth.credentials.email', '');
    }
    
    done(null, _.find(users, { email: email }));
  });

  server.method('auth.saveAccount', function(request, user, done) {
    users.push(user);
    done(null, user);
  });

  server.start(function(err) {
    if (err) {
      return console.error(err);
    }

    console.log('Server started at:', server.info.uri);
  });
});
