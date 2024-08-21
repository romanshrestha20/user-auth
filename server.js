const express = require('express');
const path = require('path');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const configurePassport = require('./config/passport');
const authRouter = require('./routes/auth');
const expressLayouts = require('express-ejs-layouts');
const { checkAuthenticated } = require('./middleware/auth');
const methodOverride = require('method-override');

// Initialize the app
const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret', // Use environment variable for secret
    resave: false,
    saveUninitialized: false
}));

// Passport configuration and middleware
configurePassport(passport);
app.use(passport.initialize());
app.use(passport.session());

// Flash messages
app.use(flash());

// Global variables for flash messages
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

// Use express-ejs-layouts middleware
app.use(expressLayouts);
app.set('layout', 'layouts/layout'); // Specify the layout file

// Allow the use of PUT and DELETE methods
app.use(methodOverride('_method'));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// serve static files
app.use('/uploads', express.static(path.join(__dirname, 'public')));

// Routes
app.use('/users', authRouter);

// Basic route with authentication
app.get('/', checkAuthenticated, (req, res) => {
    res.render('dashboard', { user: req.user, title: 'Dashboard' });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Internal Server Error');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
