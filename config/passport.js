const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const GitHubStrategy = require('passport-github2').Strategy;
const bcrypt = require('bcryptjs');
const { getUserByEmail, getUserById, createUser } = require('../services/userService');

const configurePassport = (passport) => {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: '/users/google/callback'
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const user = await getUserByEmail(profile.emails[0].value);
            if (user) {
                return done(null, user);
            } else {
                const newUser = await createUser(profile.displayName, profile.emails[0].value, null, profile.id);
                return done(null, newUser);
            }
        } catch (err) {
            return done(err);
        }
    }));


    passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
        try {
            const user = await getUserByEmail(email);

            if (!user) {
                return done(null, false, { message: 'No user with that email' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Password incorrect' });
            }
        } catch (err) {
            return done(err);
        }
    }));

    passport.serializeUser((user, done) => {
        done(null, user.user_id);
    });

    passport.deserializeUser(async (user_id, done) => {
        try {
            const user = await getUserById(user_id);
            if (!user) {
                return done(new Error('User not found'), null);
            }
            done(null, user);
        } catch (err) {
            done(err);
        }
    });
};

module.exports = configurePassport;
