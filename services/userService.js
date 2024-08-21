const crypto = require('crypto');
const pool = require('../config/db');
const { sendVerificationEmail } = require('../config/mailConfig');


const baseUrl = process.env.BASE_URL || 'http://localhost:4000';

// Retrieve user by email
const getUserByEmail = async (email) => {
    if (!email) {
        throw new Error('Email is required.');
    }
    try {
        const res = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        return res.rows[0] || null;
    } catch (error) {
        console.error('Error retrieving user by email:', error.message);
        throw error;
    }
};

// Retrieve user by ID
const getUserById = async (user_id) => {
    if (!user_id) {
        throw new Error('User ID is required.');
    }
    try {
        const res = await pool.query('SELECT * FROM users WHERE user_id = $1', [user_id]);
        return res.rows[0] || null;
    } catch (error) {
        console.error('Error retrieving user by ID:', error.message);
        throw error;
    }
};

// Create a new user
// Create a new user
const createUser = async (name, email, password = null, baseUrl) => {
    if (!name || !email) {
        throw new Error('Name and email are required.');
    }

    // Generate a verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now

    try {
        const res = await pool.query(
            `INSERT INTO users 
            (name, email, password, email_verified, verification_token, verification_token_expires) 
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [name, email, password, false, verificationToken, verificationTokenExpires]
        );

        const user = res.rows[0];

        // Send verification email
        await sendVerificationEmail(user.email, verificationToken, baseUrl);

        return user;
    } catch (error) {
        console.error('Error creating user:', error.message);
        throw error;
    }
};



const verifyEmail = async (token) => {
    try {
        const res = await pool.query(
            `SELECT * FROM users WHERE verification_token = $1 AND verification_token_expires > NOW()`,
            [token]
        );

        const user = res.rows[0];

        if (!user) {
            throw new Error('Invalid or expired verification token.');
        }

        await pool.query(
            `UPDATE users SET email_verified = true, verification_token = NULL, verification_token_expires = NULL WHERE user_id = $1 RETURNING *`,
            [user.user_id]
        );

        return user;
    } catch (error) {
        console.error('Error verifying email:', error.message);
        throw error;
    }
};

// Update user details (name, email, password)
const updateUser = async (user) => {
    const { user_id, name, email, password } = user;

    if (!user_id || !name || !email) {
        throw new Error('User ID, name, and email are required.');
    }

    try {
        // Check if user exists before updating
        const existingUser = await getUserById(user_id);
        if (!existingUser) {
            throw new Error('User not found');
        }

        const res = await pool.query(
            'UPDATE users SET name = $1, email = $2, password = $3 WHERE user_id = $4 RETURNING *',
            [name, email, password || existingUser.password, user_id]
        );
        return res.rows[0];
    } catch (error) {
        console.error('Error updating user:', error.message);
        throw error;
    }
};

// Update user password
const updateUserPassword = async ({ userId, password }) => {
    if (!userId || !password) {
        throw new Error('User ID and password are required.');
    }

    try {
        const res = await pool.query(
            'UPDATE users SET password = $1 WHERE user_id = $2 RETURNING *',
            [password, userId]
        );
        return res.rows[0];
    } catch (error) {
        console.error('Error updating password:', error.message);
        throw error;
    }
};

// Update user token and token expiry
const updatetoken = async ({ token, token_expires, email }) => {
    if (!token || !token_expires || !email) {
        throw new Error('Token, token expiry, and email are required.');
    }

    try {
        const res = await pool.query(
            'UPDATE users SET token = $1, token_expires = $2 WHERE email = $3 RETURNING *',
            [token, token_expires, email]
        );
        return res.rows[0];
    } catch (error) {
        console.error('Error updating token:', error.message);
        throw error;
    }
};

// Retrieve user by token
const getUserByToken = async (token) => {
    if (!token) {
        throw new Error('Token is required.');
    }

    try {
        const res = await pool.query('SELECT * FROM users WHERE token = $1', [token]);
        return res.rows[0] || null;
    } catch (error) {
        console.error('Error retrieving user by token:', error.message);
        throw error;
    }
};

// Delete user by ID
const deleteUser = async (user_id) => {
    if (!user_id) {
        throw new Error('User ID is required.');
    }

    try {
        // Check if user exists before attempting to delete
        const user = await getUserById(user_id);
        if (!user) {
            throw new Error('User not found');
        }

        const res = await pool.query('DELETE FROM users WHERE user_id = $1 RETURNING *', [user_id]);
        return res.rows[0] || null; // Return the deleted user or null if not found
    } catch (error) {
        console.error('Error deleting user:', error.message);
        throw error;
    }
};

module.exports = {
    getUserByEmail,
    getUserById,
    createUser,
    getUserByToken,
    updatetoken,
    updateUserPassword,
    deleteUser,
    updateUser,
    verifyEmail
};
