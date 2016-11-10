const Hapi = require('hapi');
const _ = require('lodash');

const server = new Hapi.Server();
server.connection({ host: 'localhost', port: 8000 });

const users = [];

const cookieOptions = {
  ttl: 365 * 24 * 60 * 60 * 1000,
  path: '/',
  encoding: 'iron',
  password: 'this-must-be-a-very-long-string-now',
  isSecure: false
};

server.register({
  register: require('../'),
  options: {
    getAccount: 'auth.getAccount',
    saveAccount: 'auth.saveAccount',
    loginPathTemplate: 'auth.loginPathTemplate',
    redirectTo: '/auth/login',
    cookieOptions,
    cookieName: 'auth'
  }
}, {
  routes: {
    prefix: '/auth'
  }
}, (err) => {
  if (err) {
    server.log(['hapi-auth-email', 'error'], err);
  }
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

  // server.state('auth', cookieOptions);

  server.method('auth.getAccount', (request, email, done) => {
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

    done(null, _.find(users, { email }));
  });

  server.method('auth.saveAccount', (request, user, done) => {
    if (user.password) {
      server.log(['hapi-auth-email', 'warning'], { message: `Normally you\'d email the user here. New user password is ${user.password}` });
      // you'd also not want to save the password in the user object.
      const index = _.indexOf(users, _.find(users, { email: user.email }));
      users.splice(index, 1, user);
    } else {
      users.push(user);
    }

    done(null, user);
  });

  server.method('auth.loginPathTemplate', (request, reply, data, output, done) => {
    done(null, `${output} TEST`);
  });

  server.start((startErr) => {
    if (startErr) {
      return server.log(['hapi-auth-email', 'error'], startErr);
    }
    console.log('Server started at:', server.info.uri);
  });
});
