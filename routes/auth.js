const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const { getUserByEmail, getUserByToken, updatetoken, updateUserPassword } = require('../services/userService');
const { sendResetEmail, generateResetToken } = require('../config/mailConfig');

// Redirect to Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Handle Google OAuth callback
router.get('/google/callback', (req, res, next) => {
    passport.authenticate('google', { failureRedirect: '/auth/login' })(req, res, next);
}, (req, res) => {
    try {
        res.redirect('/');
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Render registration form
router.get('/register', (req, res) => {
    res.render('register');
});

// Render login form
router.get('/login', (req, res) => {
    res.render('login');
});

// Handle registration form submission
router.post('/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    try {
        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).json({ error: 'Please fill in all fields' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        const existingUser = await getUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await createUser(name, email, hashedPassword);

        res.json({ message: 'User registered successfully', user: newUser });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Handle login form submission
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/auth/login',
        failureFlash: true
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
    res.render('users/email-confirmation');
});

// Route to handle email confirmation for password reset
router.post('/email-confirmation', async (req, res) => {
    const { email } = req.body;

    try {
        console.log('Received request to send reset email for:', email);

        const user = await getUserByEmail(email); 
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const token = generateResetToken();
        const resetTokenExpiration = new Date(Date.now() + 3600000); // 1 hour

        console.log('Generated reset token:', token);

        const updatedUser = await updatetoken({ 
            ...user,
            reset_token: token,
            reset_token_expires: resetTokenExpiration
        });

        if (!updatedUser) {
            return res.status(500).json({ error: 'Failed to update token' });
        }

        console.log('Sending reset email to:', email);

        await sendResetEmail(email, token, req);

        res.json({ message: 'Email sent successfully' });
    } catch (error) {
        console.error('Error handling email confirmation:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Render reset password form
router.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const user = await getUserByToken(token);
        if (!user) {
            return res.status(400).json({ error: 'Invalid token' });
        } else if (user.reset_token_expires < Date.now()) {
            return res.status(400).json({ error: 'Token expired' });
        } else {
            res.render('users/reset-password', { token });
        }
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Handle reset password form submission
router.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    try {
        // Validate password
        if (!password || !confirmPassword) {
            return res.status(400).json({ error: 'Please fill in all fields' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        // Find user by token
        const user = await getUserByToken(token);
        if (!user) {
            return res.status(400).json({ error: 'Invalid token' });
        } else if (user.reset_token_expires < Date.now()) {
            return res.status(400).json({ error: 'Token expired' });
        }

        // Hash new password and update user
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await updateUserPassword({
            userId: user.id,
            password: hashedPassword
        });

        res.json({ message: 'Password reset successfully' });
        console.log('Password reset successfully');
    } catch (error) {
        console.error('Error resetting password:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
