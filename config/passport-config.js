// config/passport-config.js
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const bcrypt = require('bcryptjs');
const SECRET_KEY = process.env.JWT_SECRET;
const { getUserByEmail, getUserById, createUser } = require('../services/userService');

const configurePassport = (passport) => {

    // Google OAuth Strategy
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: '/auth/google/callback'
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
            console.error('Error with Google Strategy:', err);
            return done(err);
        }
    }));

    // Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        console.log('Attempting to authenticate:', email);
        const user = await getUserByEmail(email);
        if (!user) {
            console.log('No user found with that email');
            return done(null, false, { message: 'No user with that email' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            console.log('Password matches');
            return done(null, user);
        } else {
            console.log('Password incorrect');
            return done(null, false, { message: 'Password incorrect' });
        }
    } catch (err) {
        console.error('Error during authentication:', err);
        return done(err);
    }
}));




    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await getUserById(id);
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
