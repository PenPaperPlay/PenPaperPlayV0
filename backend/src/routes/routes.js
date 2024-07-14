import express, { Router } from "express";
import {
    registration,
    login,
    logout,
    forgotPassword,
    verifyOTP,
    resetPassword,
} from "../controllers/authController.js";
import {
    getUser,
    updateUserProfile
} from "../controllers/profileController.js"
import { authenticateUser } from "../middleware/authenticateUser.js";

const routes = express.Router();


routes.post("/registration", registration)
routes.post("/login", login)
routes.post("/logout", logout)
routes.get("/profile", authenticateUser, getUser)
routes.patch("/profile/:id", authenticateUser, updateUserProfile)
routes.post("/forgot-password", forgotPassword)
routes.post("/verify-otp", verifyOTP)
routes.post("/reset-password", resetPassword)

export default routes;