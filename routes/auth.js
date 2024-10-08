// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const {
    getUserByEmail, createUser, getUserByToken, getUserById, updatetoken, updateUserPassword, deleteUser, updateUser
} = require('../services/userService');
const { generateToken, sendResetEmail, sendVerificationEmail } = require('../config/mailConfig');
// Redirect to Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Handle Google OAuth callback
router.get('/google/callback', (req, res, next) => {
    passport.authenticate('google', { failureRedirect: '/users/login' })(req, res, next);
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
    res.render('login', { title: 'Login' });
});

const baseUrl = process.env.BASE_URL || 'http://localhost:4000';

router.post('/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    try {
        if (!name || !email || !password || !confirmPassword) {
            req.flash('error_msg', 'Please fill in all fields');
            return res.redirect('/users/register');
        }

        if (password.length < 6) {
            req.flash('error_msg', 'Password must be at least 6 characters');
            return res.redirect('/users/register');
        }

        const emailRegex = /\S+@\S+\.\S+/;
        if (!emailRegex.test(email)) {
            req.flash('error_msg', 'Invalid email format');
            return res.redirect('/users/register');
        }

        if (password !== confirmPassword) {
            req.flash('error_msg', 'Passwords do not match');
            return res.redirect('/users/register');
        }

        const existingUser = await getUserByEmail(email);
        if (existingUser) {
            req.flash('error_msg', 'Email is already registered');
            return res.redirect('/users/register');
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await createUser(name, email, hashedPassword, baseUrl);
        req.flash('success_msg', 'User registered successfully. Please check your email to verify your account.');
        res.redirect('/users/login');
    } catch (error) {
        console.error('Error during registration:', error.message);
        req.flash('error_msg', 'Server error');
        res.redirect('/users/register');
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
            return res.redirect('/users/login');
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
        res.redirect('/users/login');
    });
});

// Render email confirmation form
router.get('/email-confirmation', (req, res) => {
    res.render('users/email-confirmation', { title: 'Email Confirmation' });
});

// Route to handle email confirmation for password reset
router.post('/email-confirmation', async (req, res) => {
    const { email } = req.body;

    try {
        console.log('Received request to send reset email for:', email);

        const user = await getUserByEmail(email);
        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/users/email-confirmation');
        }

        const token = generateToken();
        const resetTokenExpiration = new Date(Date.now() + 3600000); // 1 hour

        console.log('Generated reset token:', token);

        const updatedUser = await updatetoken({
            ...user,
            token: token,
            token_expires: resetTokenExpiration
        });

        if (!updatedUser) {
            req.flash('error_msg', 'Failed to update token');
            return res.redirect('/users/email-confirmation');
        }

        await sendResetEmail(email, token, req);
        req.flash('success_msg', 'Reset email sent successfully');
        return res.redirect('/users/login');
    } catch (error) {
        console.error('Error handling email confirmation:', error.message);
        if (!res.headersSent) {
            req.flash('error_msg', 'Server error');
            return res.status(500).json({ error: 'Server error' });
        }
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
        if (!password || !confirmPassword) {
            req.flash('error_msg', 'Please fill in all fields');
            return res.redirect(`/users/reset-password/${token}`);
        }

        if (password.length < 6) {
            req.flash('error_msg', 'Password must be at least 6 characters');
            return res.redirect(`/users/reset-password/${token}`);
        }

        if (password !== confirmPassword) {
            req.flash('error_msg', 'Passwords do not match');
            return res.redirect(`/users/reset-password/${token}`);
        }

        const user = await getUserByToken(token);
        if (!user) {
            req.flash('error_msg', 'Invalid token');
            return res.redirect(`/users/reset-password/${token}`);
        } else if (user.token_expires < Date.now()) {
            req.flash('error_msg', 'Token expired');
            return res.redirect(`/users/reset-password/${token}`);
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await updateUserPassword({
            userId: user.user_id,
            password: hashedPassword
        });

        req.flash('success_msg', 'Password reset successfully');
        res.redirect('/users/login');
    } catch (error) {
        console.error('Error resetting password:', error.message);
        req.flash('error_msg', 'Server error');
        res.redirect(`/users/reset-password/${token}`);
    }
});


// verify email
router.get('/verify-email/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const user = await verifyEmail(token);
        req.flash('success_msg', 'Email verified successfully');
        res.redirect('/users/login');
    } catch (error) {
        res.status(400).send(error.message);
    }
});



// Handle user deletion
router.delete('/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const deletedUser = await deleteUser(id);

        if (!deletedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        req.logout(err => {
            if (err) {
                return next(err);
            }
            req.flash('success_msg', 'Your account has been removed. You are logged out');
            res.redirect('/users/login');
        });
    } catch (error) {
        console.error('Error deleting user:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Handle user updates
router.put('/:id', async (req, res) => {
    const { id } = req.params;
    const { name, email, password } = req.body;
    console.log('id:', id);
    console.log('name:', name);
    console.log('email:', email);

    try {
        const user = await getUserById(id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (password) {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            const updatedUser = await updateUserPassword({
                userId: id,
                password: hashedPassword
            });
            req.flash('success_msg', 'Password updated successfully');
            return res.redirect('/');
        } else {
            const updatedUser = await updateUser({
                user_id: id,
                name: name || user.name,
                email: email || user.email
            });

            if (!updatedUser) {
                return res.status(500).json({ error: 'Failed to update user' });
            }

            req.flash('success_msg', 'User updated successfully');
            res.redirect('/');
        }
    } catch (error) {
        console.error('Error updating user:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
