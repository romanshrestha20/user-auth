const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();
// Function to generate reset token
function generateResetToken() {
    return crypto.randomBytes(20).toString('hex');
}

// Function to send reset password email confirmation
async function sendResetEmail(email, token, req) {
    try {
        let transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: process.env.EMAIL,
                pass: process.env.EMAIL_PASS
            }
        });

        await transporter.sendMail({
            from: process.env.EMAIL,
            to: email,
            subject: 'Password Reset Request',
            html: `<p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
            <p>Please click on the following link, or paste this into your browser to complete the process:</p>
            <p><a href="http://${req.headers.host}/auth/reset-password/${token}">Reset Password Link</a></p>
            <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>`
        });

        console.log('Password reset email sent successfully.');
    } catch (error) {
        console.error('Error sending email:', error);
        throw new Error('Error sending email');
    }
}

module.exports = {
    generateResetToken,
    sendResetEmail
};