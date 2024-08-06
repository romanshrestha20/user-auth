require('dotenv').config(); // Load environment variables from .env file

const JWT_SECRET = process.env.JWT_SECRET 

module.exports = {
    JWT_SECRET
};