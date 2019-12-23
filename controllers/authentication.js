const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  // user has already had their mail and password
  // just need to give them a token
  res.send({ token: tokenForUser(req.user) });
};

exports.signup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res
      .status(422)
      .send({ error: 'You must provide email and password' });
  }

  // see if a user with the given email exists
  User.findOne({ email }, (err, existingUser) => {
    if (existingUser) {
      return res.status(422).send({ error: 'email is in use' });
    }
    // if a user with email does exist , return an error
    const user = new User({
      email,
      password
    });
    user.save(function(err) {
      if (err) {
        return next(err);
      }
      // if a user with email does NOT exist
      res.json({ token: tokenForUser(user) });
    });
  });
};
