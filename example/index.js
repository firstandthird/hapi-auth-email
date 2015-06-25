var Hapi = require('hapi');
var _ = require('lodash');

var server = new Hapi.Server();
server.connection({ host: 'localhost', port: 8000 });

var users = [];

server.register({
  register: require('../'),
  options: {
    getAccount: 'auth.getAccount',
    saveAccount: 'auth.saveAccount',
    redirectTo: '/auth/login'

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

  server.method('auth.getAccount', function(request, done) {
    done(null, _.find(users, { email: _.get(request, 'auth.credentials.email', '') }));
  });

  server.method('auth.saveAccount', function(request, user, done) {
    users.push(user);
    done(null);
  });

  server.start(function(err) {
    if (err) {
      return console.error(err);
    }
    
    console.log('Server started at:', server.info.uri);
  });
});
