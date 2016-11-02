'use strict';
const code = require('code');   // assertion library
const Lab = require('lab');
const lab = exports.lab = Lab.script();
const Hapi = require('hapi');
const emailAuth = require('../');

lab.experiment('hapi-auth-email views', () => {
  let server;
  lab.beforeEach((done) => {
    server = new Hapi.Server({
      debug: {
        log: ['hapi-auth-email', 'warning', 'info', 'error']
      }
    });
    server.connection({ host: 'localhost', port: 8000 });
    server.register({
      register: emailAuth,
      options: {
        getAccount: (request, getAccountDone) => {
          getAccountDone(null, {});
        }
      }
    }, () => {
      server.start(done);
    });
  });

  lab.afterEach((done) => {
    server.stop(done);
  });

  lab.test('serves a login page', (done) => {
    server.inject({
      url: '/login',
      method: 'GET'
    }, (response) => {
      code.expect(response.statusCode).to.equal(200);
      done();
    });
  });
  lab.test('serves a register page', (done) => {
    server.inject({
      url: '/register',
      method: 'GET'
    }, (response) => {
      code.expect(response.statusCode).to.equal(200);
      done();
    });
  });
  lab.test('serves a reset page', (done) => {
    server.inject({
      url: '/reset',
      method: 'GET'
    }, (response) => {
      code.expect(response.statusCode).to.equal(200);
      done();
    });
  });
});
