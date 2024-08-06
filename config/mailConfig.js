const crypto = require('crypto');
const nodemailer = require('nodemailer');

require('dotenv').config();

const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
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
function createEmailContent(subject, htmlContent) {
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

// Function to send OTP email
const sendOTPEmail = async (email, otp) => {
    const htmlContent = `
    <p>Your OTP is: <strong>${otp}</strong></p>
    <p>This OTP is valid for 10 minutes. Please do not share it with anyone.</p>
    `;
    const emailOptions = createEmailContent('OTP for Password Reset', htmlContent);
    emailOptions.to = email;
    await sendEmail(emailOptions);
}

// Function to generate reset token


// Function to send reset email
const sendResetEmail = async (email, token, req) => {
    const resetLink = `http://${req.headers.host}/auth/reset-password/${token}`;
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

module.exports = {
    sendResetEmail,
    sendOTPEmail,
    generateOTP
};
