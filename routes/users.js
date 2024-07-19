const express = require('express');
const router = express.Router();
const { getUsers, getUserById, createUser } = require('../services/userService');

// Fetch all users
router.get('/', async (req, res) => {
    try {
        const users = await getUsers();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Fetch user by ID
router.get('/:id', async (req, res) => {
    const userId = parseInt(req.params.id, 10); // Ensure ID is an integer
    if (isNaN(userId)) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }

    try {
        const user = await getUserById(userId);
        if (user) {
            res.json(user);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create a new user
router.post('/', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;
        // Add your validation and creation logic here...
        const newUser = await createUser(name, email, password);
        res.json(newUser);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
