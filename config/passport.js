const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const pgPool = require('./database');
const validPassword = require('../lib/passwordUtils').validPassword;

const customFields = {
  usernameField: 'uname',
  passwordField: 'pw',
};

const verifyCallback = async (username, password, done) => {
  try {
    const query = 'SELECT * FROM users WHERE username = $1';
    const values = [username];
    const res = await pgPool.query(query, values);

    const user = res.rows[0];

    if (!user || !user.hash || !user.salt) {
      return done(null, false);
    }

    const isValid = validPassword(password, user.hash, user.salt);

    if (isValid) {
      return done(null, user);
    } else {
      return done(null, false);
    }
  } catch (err) {
    done(err);
  }
};

const strategy = new LocalStrategy(customFields, verifyCallback);

passport.use(strategy);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (userId, done) => {
  try {
    const query = 'SELECT * FROM users WHERE id = $1';
    const values = [userId];
    const res = await pgPool.query(query, values);
    done(null, res.rows[0]); // Return the user object
  } catch (err) {
    done(err, null);
  }
});
