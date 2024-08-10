module.exports = {
    checkAuthenticated: (req, res, next) => {
        try {
            if (req.isAuthenticated()) {
                return next();
            }
            req.flash('error_msg', 'Please log in to view that resource');
            res.redirect('/users/login');
        } catch (error) {
            // Handle any errors that occur during authentication
            console.error(error);
            res.status(500).send('Internal Server Error');
        }
    }
};
