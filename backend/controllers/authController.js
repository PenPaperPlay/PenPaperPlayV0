import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import otpGenerator from "otp-generator";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

import { UserRole } from "../enums/user.enum.js";
import { User } from "../database/models/users.js";


// Helper function to get the directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

export const registration = async (req, res, next) => {
    try {
        const { name, email, password, role } = req.body;

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res
                .status(400)
                .json({ message: "User already exists with this email" });
        }

        if (![UserRole.PLAYER, UserRole.COACH].includes(role)) {
            return res.status(400).json({ message: "Invalid role" });
        }

        let newUser;
        if (password) {
            // If the user registers with a password
            const hashPassword = bcryptjs.hashSync(password, 10);

            newUser = new User({
                name: name,
                email: email,
                password: hashPassword,
                role: role,
            });
        }

        const savedUser = await newUser.save();

        const { password: Password, ...rest } = savedUser._doc;

        const payload = { user: { id: savedUser.id } };
        const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, {
            expiresIn: "1h",
        });

        return res
            .status(201)
            .json({ message: "User registered successfully", user: rest, token });
    } catch (error) {
        return res
            .status(400)
            .json({ message: "Registration failed", error: error.message });
    }
};

export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid email" });
        }
        const isPassword = bcryptjs.compareSync(password, user.password);
        if (!isPassword) {
            return res.status(401).json({ message: "Invalid Password" });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET_KEY,
            { expiresIn: "1h" }
        );

        res.cookie("token", token, {
            httpOnly: true,
        });
        const { password: hashPassword, ...rest } = user._doc;
        res.status(200).json({ message: "Login sucessfully", user: rest, token });
    } catch (error) {
        return res
            .status(500)
            .json({ massage: ` Login failed becouse of ${error}` });
    }
};

export const logout = async (req, res) => {
    try {
        res.clearCookie("token");
        res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
        res.status(500).json({ message: "Logout failed" });
    }
};

function generateOTP() {
    // Generate a random 6-digit number
    const otp = Math.floor(100000 + Math.random() * 900000);
    return otp.toString(); // Convert to string to ensure it's always 6 digits
}

// Assume otpMap is initialized as an outer map
const otpMap = new Map();

export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        // Check if the email exists in the database
        const user = await User.findOne({ email });

        if (!user) {
            return res
                .status(404)
                .json({ message: "User not found with this email" });
        }

        // Generate OTP (numeric only)
        const otp = generateOTP();

        console.log(otp);

        // Store OTP and related data securely for this specific user in otpMap
        otpMap.set(email, {
            otp,
            expiry: Date.now() + 5 * 60 * 1000, // 5-minute expiry
        });

        // Send the OTP to the user's email
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.GMAIL, // replace with your email
                pass: process.env.PASSWORD, // replace with your email password or app-specific password
            },
        });

        // Read the HTML template
        const templatePath = path.join(
            __dirname,
            "../view",
            "forgotpasswordmailtemplate.html"
        );
        let emailTemplate = fs.readFileSync(templatePath, "utf8");

        // Replace placeholders with actual values
        emailTemplate = emailTemplate.replace("{{name}}", user.name);
        emailTemplate = emailTemplate.replace("{{otp}}", otp);

        const mailOptions = {
            from: process.env.GMAIL,
            to: email,
            subject: "Password Reset OTP",
            html: emailTemplate,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending email:", error);
                return res
                    .status(500)
                    .json({ message: "Error sending OTP email", error: error.message });
            }

            console.log("Email sent:", info.response, otpMap);
            res
                .status(200)
                .json({ message: "OTP sent successfully. Check your email." });
        });
    } catch (error) {
        console.error("Forgot Password Error:", error);
        res
            .status(500)
            .json({ message: "Internal server error", error: error.message });
    }
};

export const verifyOTP = async (req, res) => {
    try {
        const { email, enteredOTP } = req.body;

        const storedOTPData = otpMap.get(email);

        if (!storedOTPData || Date.now() > storedOTPData.expiry) {
            otpMap.delete(email); // Remove expired entries or non-existent emails
            return res
                .status(400)
                .json({
                    message: "OTP expired or not found. Please request a new OTP.",
                });
        }

        if (enteredOTP !== storedOTPData.otp) {
            return res
                .status(400)
                .json({ message: "Invalid OTP. Please enter the correct OTP." });
        }

        // If OTP is valid, generate a reset token for password reset
        const resetToken = jwt.sign({ email }, process.env.RESET_PASSWORD_SECRET, {
            expiresIn: "5m",
        });

        // Store the reset token securely for this specific user in the otpMap
        storedOTPData.resetToken = resetToken;

        // Set the reset token in the user's cookies
        res.cookie("resetPasswordToken", resetToken, {
            httpOnly: true,
            secure: true, // Use 'true' if using HTTPS
            maxAge: 5 * 60 * 1000, // 5 minutes expiration
            sameSite: "strict", // Adjust as needed
        });

        res
            .status(200)
            .json({
                message: "OTP verified successfully. Proceed to reset password.",
            });
    } catch (error) {
        console.error("OTP Verification Error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const resetPassword = async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        const resetToken = req.cookies.resetPasswordToken;

        if (!resetToken) {
            return res
                .status(401)
                .json({ message: "Unauthorized: No reset token found" });
        }

        // Verify the reset token
        jwt.verify(
            resetToken,
            process.env.RESET_PASSWORD_SECRET,
            async (err, decoded) => {
                if (err || decoded.email !== email) {
                    return res
                        .status(401)
                        .json({ message: "Invalid or expired reset token" });
                }

                // Proceed with updating the user's password
                const user = await User.findOne({ email });

                if (!user) {
                    return res.status(404).json({ message: "User not found" });
                }

                // Update the user's password logic here using bcrypt or any password hashing method
                user.password = bcryptjs.hashSync(newPassword, 10);
                await user.save();

                res.clearCookie("resetPasswordToken"); // Clear the reset token cookie after password reset

                res.status(200).json({ message: "Password reset successfully" });
            }
        );
    } catch (error) {
        console.error("Password Reset Error:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};
