const pool = require('../config/db');

// Retrieve user by email
const getUserByEmail = async (email) => {
    const res = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return res.rows[0];
};

// Retrieve user by ID
const getUserById = async (id) => {
    const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return res.rows[0];
};

// Create a new user
const createUser = async (name, email, password = null, googleId = null) => {
    if (!name || !email) {
        throw new Error('Name and email are required.');
    }

    const res = await pool.query(
        'INSERT INTO users (name, email, password, google_id) VALUES ($1, $2, $3, $4) RETURNING *',
        [name, email, password, googleId]
    );
    return res.rows[0];
};

// Update user details (name, email, password)
const updateUser = async (user) => {
    const { id, name, email, password } = user;

    if (!id || !name || !email) {
        throw new Error('ID, name, and email are required.');
    }

    // Check if user exists before updating
    const existingUser = await getUserById(id);
    if (!existingUser) {
        throw new Error('User not found');
    }

    try {
        const res = await pool.query(
            'UPDATE users SET name = $1, email = $2, password = $3 WHERE id = $4 RETURNING *',
            [name, email, password || existingUser.password, id]
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
            'UPDATE users SET password = $1 WHERE id = $2 RETURNING *',
            [password, userId]
        );
        return res.rows[0];
    } catch (error) {
        console.error('Error updating password:', error.message);
        throw error;
    }
};

// Update user token and token expiry
const updatetoken = async (user) => {
    const { token, token_expires, email } = user;

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
    const res = await pool.query('SELECT * FROM users WHERE token = $1', [token]);
    return res.rows[0];
};

// Delete user by ID
const deleteUser = async (id) => {
    try {
        // Check if user exists before attempting to delete
        const user = await getUserById(id);
        if (!user) {
            throw new Error('User not found');
        }

        const res = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
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
    updateUser
};
