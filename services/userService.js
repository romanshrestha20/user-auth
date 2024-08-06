const e = require('connect-flash');
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

const storeOtp = async (email, otp, otpExpiration) => {
    try {
        const query = `UPDATE users SET otp = $1, otp_expires = $2 WHERE email = $3 RETURNING id`;
        const otpExpirationISOString = otpExpiration.toISOString();
        const values = [otp, otpExpirationISOString, email];
        const res = await pool.query(query, values);
        return res.rowCount > 0;
    } catch (error) {
        console.error('Error storing OTP:', error.message);
        throw new Error('Error storing OTP');
    }
}


// get otp from db
const getOtp = async (email) => {
    try {
        const query = `SELECT otp, otp_expires FROM users WHERE email = $1`;
        const res = await pool.query(query, [email]);
        return res.rows[0] || {}; // Return an empty object if no data is found
    } catch (error) {
        console.error('Error getting OTP:', error.message);
        throw new Error('Error getting OTP');
    }
}

const getOtpByValue = async (otp) => {
    try {
        const query = `SELECT otp, otp_expires FROM users WHERE otp = $1`;
        const res = await pool.query(query, [otp]);
        return res.rows[0] || {}; // Return an empty object if no data is found
    } catch (error) {
        console.error('Error getting OTP:', error.message);
        throw new Error('Error getting OTP');
    }
}



const getUserByToken = async (token) => {
    try {
        const res = await pool.query('SELECT * FROM users WHERE token = $1', [token]);
        return res.rows[0];
    } catch (error) {
        console.error('Error getting user by token:', error.message);
        throw error;
    }
};



const updatetoken = async (email, token, tokenExpires) => {
    try {
        const res = await pool.query(
            'UPDATE users SET token = $1, token_expires = $2 WHERE email = $3 RETURNING *',
            [token, tokenExpires, email]
        );
        return res.rows[0];
    } catch (error) {
        console.error('Error updating token:', error.message);
        throw error;
    }
};

// validiate token expires
const validateTokenExpires = async (email) => {
    try {
        const res = await pool.query('SELECT token_expires FROM users WHERE email = $1', [email]);
        return res.rows[0];
    } catch (error) {
        console.error('Error getting token expires:', error.message);
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
        const res = await pool.query('DELETE FROM users WHERE id = $1', [id]);
        return res.rowCount > 0;
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
    storeOtp,
    getOtp,
    getOtpByValue,
    deleteUser,
    validateTokenExpires
};
