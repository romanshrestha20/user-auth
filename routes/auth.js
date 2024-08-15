const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const { getUserByEmail, createUser, getUserByToken, getUserById, updatetoken, updateUserPassword, deleteUser,
    updateUser
 } = require('../services/userService');
const { sendResetEmail, generateToken } = require('../config/mailConfig');

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

// Handle registration form submission
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
        // check if email format is valid
        const emailRegex = /\S+@\S+\.\S+/;
        if (!emailRegex.test(email)) {
            req.flash('error_msg', 'Invalid email format');
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

        await createUser(name, email, hashedPassword);
        req.flash('success_msg', 'User registered successfully');
        res.redirect('/users/login');
    } catch (error) {
        console.error(error.message);
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

        // Check if the user exists
        const user = await getUserByEmail(email);
        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/users/email-confirmation'); // Stop execution
        }

        // Generate a reset token and expiration time
        const token = generateToken();
        const resetTokenExpiration = new Date(Date.now() + 3600000); // 1 hour

        console.log('Generated reset token:', token);

        // Update the user's record with the reset token and expiration
        const updatedUser = await updatetoken({
            ...user,
            token: token,
            token_expires: resetTokenExpiration
        });

        if (!updatedUser) {
            req.flash('error_msg', 'Failed to update token');
            return res.redirect('/users/email-confirmation'); // Stop execution
        }

        // Send the reset email
        await sendResetEmail(email, token, req);
        req.flash('success_msg', 'Reset email sent successfully');
        return res.redirect('/users/login'); // Stop execution
    } catch (error) {
        console.error('Error handling email confirmation:', error.message);

        // Check if headers have already been sent before sending another response
        if (!res.headersSent) {
            req.flash('error_msg', 'Server error');
            return res.status(500).json({ error: 'Server error' }); // Stop execution
        }
    }
});


// Render reset password form
router.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    res.render('users/reset-password', { title: 'Reset Password', token });
}
);

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
            userId: user.id,
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
            // Set flash message first, then redirect
    } catch (error) {
        console.error('Error deleting user:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

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
            // Update only password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            const updatedUser = await updateUserPassword({
                userId: id,
                password: hashedPassword
            });
            return res.json(updatedUser);
        } else {
            // Update name and email if no password is provided
            const updatedUser = await updateUser({
                id,
                name: name || user.name,
                email: email || user.email,
                password: user.password // Keep the current password if not updating it
            });
            req.flash('success_msg', 'User updated successfully');
            return res.redirect('/');
        }
    } catch (error) {
        console.error('Error updating user:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
