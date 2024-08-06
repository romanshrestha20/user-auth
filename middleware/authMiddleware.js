const jwt = require('jsonwebtoken');
const { jwtSecret } = require('./config');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Get the token from the Authorization header
    if (!token) {
        return res.sendStatus(401);
    }
    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden if token is invalid
        }
        req.user = user;// Set the user in the request object
        next(); // Call the next middleware
    });
}

module.exports = { authenticateToken };