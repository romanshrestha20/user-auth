const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

  // Function to test the connection to the database
  const testConnection = async () => {
    try {
      const client = await pool.connect();
      await client.query('SELECT NOW()');
      console.log('Database connected successfully');
      client.release();
    } catch (err) {
      console.error('Database connection error', err.message);
    }
  };

  testConnection();
module.exports = pool;