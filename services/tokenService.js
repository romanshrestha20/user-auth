const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config/config'); // Adjust the path to your config file

// Function to generate a JWT token for password reset
const generateResetToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email }, jwtSecret, { expiresIn: '15m' }); // 15 minutes expiration
}


// Function to verify a JWT token for password reset
const verifyResetToken = (token) => {
    return new Promise((resolve, reject) => {
        jwt.verify(token, jwtSecret, (err, decoded) => {
            if (err) {
                return reject(err);
            }
            resolve(decoded);
        });
    });
}


module.exports = { generateResetToken, verifyResetToken };
