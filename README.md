# Hapi Email Authentication

Usage:

```js
server.register({
  register: require('hapi-auth-email'),
  options: {}
}, function(err) {
  // ...
  server.auth.strategy('email', 'email', true);
});
```

Options:

 - `schemeName` - Name to register and the  auth scheme. Default: `'email'`
 - `namespace` - Path to register server methods. Default: `'auth.'`
 - `getAccount` - Method that returns a user account. Params: `request`, `callback(err, user)`. Returned user must contain the following properties: `email`, `hash`, `salt`
 - `useDefaultViews` - Set to false to disable built in views. Default: `true`
 - `redirectOnTry` - Redirect unauthenticated users when auth mode is `try`. Default: `true`
 - `redirectTo` - Url to redirect user to. Default: `'/login'`
 - `hashConfig` - Any valid https://github.com/davidmurdoch/easy-pbkdf2#options

The following addition options are only for built in views:
 - `saveAccount` - Method to save the user. Only used when using the built in views. Params: `request`, `user`, `callback(err, user)`
 - `loginPath` - Login url for built in view. Default: `'/login'`
 - `registerPath` - Registration url for built in view. Default: `'/register'`
 - `resetPassPath` - Reset url for built in view. Default `'/reset'`
 - `successEndpont` - Url to redirect to on successful login or registration when `?next` param doesn't exist. Default: `'/'`
 - `cookieName` - Cookie name for built in views. Default: `'hapi-auth-email'`
 - `cookieOptions` - Any valid Hapi cookie option.
 - `loginForm` / `registerForm` / `resetForm`
  - `name`: Name used on the form.
  - `description`: Shown under name.

Methods:

These methods may be attached to a different namespace if `options.namespace` is set.

 - `server.auth.generateHash` - Params: `user`, `password`, `callback(err, user)`
 - `server.auth.validatePassword` - Params: `user`, `password`, `callback(err, isValid)`
