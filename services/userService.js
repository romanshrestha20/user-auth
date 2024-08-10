const pool = require('../config/db');

const getUserByEmail = async (email) => {
    const res = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return res.rows[0];
};

const getUserById = async (id) => {
    const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return res.rows[0];
};

const createUser = async (name, email, password, googleId = null) => {
    const res = await pool.query(
        'INSERT INTO users (name, email, password, google_id) VALUES ($1, $2, $3, $4) RETURNING *',
        [name, email, password, googleId]
    );
    return res.rows[0];
};

const getUserByToken = async (token) => {
    const res = await pool.query('SELECT * FROM users WHERE token = $1', [token]);
    return res.rows[0];
};

const updatetoken = async (user) => {
    try {
        const res = await pool.query(
            'UPDATE users SET token = $1, token_expires = $2 WHERE email = $3 RETURNING *',
            [user.token, user.token_expires, user.email]
        );
        return res.rows[0];
    } catch (error) {
        console.error('Error updating token:', error.message);
        throw error;
    }
};

const updateUserPassword = async ({ userId, password }) => {
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

const deleteUser = async (id) => {
    try {
        const res = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
        return res.rows[0] || null; // Return the deleted user or null if not found
    } catch (error) {
        console.error('Error deleting user:', error.message);
        throw error;
    }
}


module.exports = {
    getUserByEmail,
    getUserById,
    createUser,
    getUserByToken,
    updatetoken,
    updateUserPassword,
    deleteUser
};
