const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

// Function to generate tokens (for both password reset and email verification)
const generateToken = () => {
    return crypto.randomBytes(20).toString('hex');
}

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASS
    }
});

// Function to create email content
const createEmailContent = (subject, htmlContent) => {
    return {
        from: process.env.EMAIL,
        subject,
        html: htmlContent,
    };
}

// Function to send email
const sendEmail = async (options) => {
    try {
        await transporter.sendMail(options);
        console.log(`${options.subject} email sent successfully.`);
    } catch (error) {
        console.error(`Error sending ${options.subject} email:`, error);
        throw new Error('Error sending email');
    }
}

// Function to send password reset email
const sendResetEmail = async (email, token, req) => {
    const resetLink = `http://${req.headers.host}/users/reset-password/${token}`;
    const htmlContent = `
    <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
    <p>Please click on the following link, or paste this into your browser to complete the process:</p>
    <p><a href="${resetLink}">Reset Password Link</a></p>
    <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
    `;
    // Create email options object to send the email
    const emailOptions = createEmailContent('Password Reset Request', htmlContent);
    emailOptions.to = email;
    await sendEmail(emailOptions);
}

// Function to send email verification email

const sendVerificationEmail = async (email, token, baseUrl) => {
    const verificationUrl = `${baseUrl}/verify-email/${token}`;
    const htmlContent = `
    <p>Please verify your email by clicking on the following link:</p>
    <p><a href="${verificationUrl}">Verify Email</a></p>
    `;
    const emailOptions = createEmailContent('Verify Your Email Address', htmlContent);
    emailOptions.to = email;
    await sendEmail(emailOptions);
}

module.exports = {
    generateToken,
    sendResetEmail,
    sendVerificationEmail
};
