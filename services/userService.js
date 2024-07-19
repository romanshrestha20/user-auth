const pool = require('../config/db');

const getUsers = async () => {
    const users = await pool.query('SELECT * FROM users');
    return users.rows;
};

const getUserById = async (id) => {
    if (typeof id !== 'number') {
        throw new Error('Invalid user ID type');
    }
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return user.rows[0] || null;  // Return null if no user found
};

const getUserByEmail = async (email) => {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return user.rows[0] || null;  // Return null if no user found
};

const createUser = async (name, email, hashedPassword, googleId = null) => {
    const newUser = await pool.query(
        'INSERT INTO users (name, email, password, google_id) VALUES ($1, $2, $3, $4) RETURNING *',
        [name, email, hashedPassword, googleId]
    );
    return newUser.rows[0];
};

module.exports = {
    getUsers,
    getUserById,
    getUserByEmail,
    createUser
};
