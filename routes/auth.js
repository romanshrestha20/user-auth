const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const { 
    getUserByEmail, 
    createUser, 
    getUserByToken, 
    updatetoken, 
    updateUserPassword, 
    storeOtp, 
    getOtpByValue, 
    deleteUser 
} = require('../services/userService');
const { sendOTPEmail, generateOTP } = require('../config/mailConfig');
const { generateResetToken, verifyResetToken } = require('../services/tokenService');
// Generate a token


// Redirect to Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Handle Google OAuth callback
router.get('/google/callback', (req, res, next) => {
    passport.authenticate('google', { failureRedirect: '/auth/login' })(req, res, next);
}, (req, res) => {
    try {
        req.flash('success_msg', 'You are now logged in with Google');
        res.redirect('/');
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Render registration form
router.get('/register', (req, res) => {
    res.render('register', { title: 'Register' });
});

// Render login form
router.get('/login', (req, res) => {
    res.render('login', { title: 'Login', user: req.user });
});

// Handle registration form submission
router.post('/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    try {
        if (!name || !email || !password || !confirmPassword) {
            req.flash('error_msg', 'Please fill in all fields');
            return res.redirect('/auth/register');
        }

        if (password.length < 6) {
            req.flash('error_msg', 'Password must be at least 6 characters');
            return res.redirect('/auth/register');
        }

        const emailRegex = /\S+@\S+\.\S+/;
        if (!emailRegex.test(email)) {
            req.flash('error_msg', 'Invalid email format');
            return res.redirect('/auth/register');
        }

        if (password !== confirmPassword) {
            req.flash('error_msg', 'Passwords do not match');
            return res.redirect('/auth/register');
        }

        const existingUser = await getUserByEmail(email);
        if (existingUser) {
            req.flash('error_msg', 'Email is already registered');
            return res.redirect('/auth/register');
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await createUser(name, email, hashedPassword);
        req.flash('success_msg', 'User registered successfully');
        res.redirect('/auth/login');
    } catch (error) {
        console.error(error.message);
        req.flash('error_msg', 'Server error');
        res.redirect('/auth/register');
    }
});

// Handle login form submission
router.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            console.error(err.message);
            return next(err);
        }
        if (!user) {
            req.flash('error_msg', 'Invalid email or password');
            return res.redirect('/auth/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error(err.message);
                return next(err);
            }
            req.flash('success_msg', 'You are now logged in');
            res.redirect('/');
        });
    })(req, res, next);
});

// Handle logout
router.get('/logout', (req, res, next) => {
    req.logout(err => {
        if (err) {
            return next(err);
        }
        req.flash('success_msg', 'You are logged out');
        res.redirect('/auth/login');
    });
});

// Render email confirmation form
router.get('/email-confirmation', (req, res) => {
    res.render('users/email-confirmation', { title: 'Email Confirmation', user: req.user, email: '' });
});

// Route to handle email confirmation for OTP
router.post('/email-confirmation', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await getUserByEmail(email);
        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.render('users/email-confirmation', {
                title: 'Email Confirmation',
                email,
                error_msg: req.flash('error_msg')
            });
        }

        const otp = generateOTP();
        const otpExpiration = new Date(Date.now() + 10 * 60 * 1000);  // 10 minutes from now

        console.log('Generated OTP:', otp);

        const otpStored = await storeOtp(email, otp, otpExpiration);
        if (!otpStored) {
            req.flash('error_msg', 'Failed to store OTP');
            return res.render('users/email-confirmation', {
                title: 'Email Confirmation',
                email,
                error_msg: req.flash('error_msg')
            });
        }

        await sendOTPEmail(email, otp);
        req.flash('success_msg', 'OTP email sent successfully');
        return res.redirect('/auth/email-confirmation');
    } catch (error) {
        console.error('Error handling email confirmation:', error.message);
        req.flash('error_msg', 'Server error');
        return res.render('users/email-confirmation', {
            title: 'Email Confirmation',
            email: req.body.email,
            error_msg: req.flash('error_msg')
        });
    }
});

// Route to handle OTP confirmation
router.post('/confirm-otp', async (req, res) => {
    const { otp } = req.body;

    try {
        if (!otp) {
            req.flash('error_msg', 'Please enter the OTP');
            return res.redirect('/auth/email-confirmation');
        }

        if (otp.length !== 6) {
            req.flash('error_msg', 'Invalid OTP length');
            return res.redirect('/auth/email-confirmation');
        }

        const otpData = await getOtpByValue(otp);

        if (!otpData || !otpData.otp || !otpData.otp_expires) {
            req.flash('error_msg', 'No OTP data available or OTP expired');
            return res.redirect('/auth/email-confirmation');
        }

        const { otp: storedOtp, otp_expires: otpExpiration, email } = otpData;
        const otpExpirationDate = new Date(otpExpiration);
        const currentDate = new Date();

        if (otp !== storedOtp || currentDate > otpExpirationDate) {
            req.flash('error_msg', 'Invalid or expired OTP');
            return res.redirect('/auth/email-confirmation');
        }

        const user = await getUserByEmail(email);
        const token = generateResetToken(user); // Pass the user object here
        const tokenExpiration = new Date(Date.now() + 10 * 60 * 1000); // Token valid for 10 minutes

        await updatetoken(email, token, tokenExpiration);

        req.flash('success_msg', 'OTP confirmed successfully');
        return res.redirect(`/auth/reset-password/${token}`);
    } catch (error) {
        console.error('Error confirming OTP:', error.message);
        req.flash('error_msg', 'Server error');
        return res.redirect('/auth/email-confirmation');
    }
});


// Render reset password form
router.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    res.render('users/reset-password', { title: 'Reset Password', token });
});

router.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    try {
        if (password !== confirmPassword) {
            req.flash('error_msg', 'Passwords do not match');
            return res.redirect(`/auth/reset-password/${token}`);
        }

        const user = await verifyResetToken(token);

        if (!user) {
            req.flash('error_msg', 'Invalid or expired token');
            return res.redirect(`/auth/reset-password/${token}`);
        }

        const { token_expires: tokenExpiration } = user;

        if (!tokenExpiration) {
            req.flash('error_msg', 'Token expiration not set');
            return res.redirect(`/auth/reset-password/${token}`);
        }

        if (new Date() > new Date(tokenExpiration)) {
            req.flash('error_msg', 'Token has expired');
            return res.redirect(`/auth/reset-password/${token}`);
        }
        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        await updateUserPassword({ userId: user.id, password: hashedPassword });
        await updatetoken(user.email, null, null);
        console.log('Updated token', token);

        req.flash('success_msg', 'Password reset successfully');
        res.redirect('/auth/login');
    } catch (error) {
        console.error('Error during password reset:', error.message);
        req.flash('error_msg', 'Server error');
        res.redirect(`/auth/reset-password/${token}`);
    }
});


// Route to delete user account
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await deleteUser(id);
        req.flash('success_msg', 'Account deleted successfully');
        res.redirect('/auth/login');
    } catch (error) {
        console.error('Error deleting account:', error.message);
        req.flash('error_msg', 'Server error');
        res.redirect('/auth/login');
    }
});

module.exports = router;
