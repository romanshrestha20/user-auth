// errorHandler.js
const errorHandler = (err, req, res, next) => {
    console.error(err.stack);

    // Check if the error has a status code
    if (err.status) {
        res.status(err.status).render('error', { title: 'Error', message: err.message });
    } else {
        // Default to 500 Internal Server Error
        res.status(500).render('error', { title: 'Error', message: 'Internal Server Error' });
    }
};


module.exports = errorHandler;
