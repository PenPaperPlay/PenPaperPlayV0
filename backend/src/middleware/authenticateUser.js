import jwt from "jsonwebtoken";
import { User } from "../database/models/users.js";
import dotenv from "dotenv";

dotenv.config()

export const authenticateUser = async (req, res, next) => {

    try {

        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({ auth: false, message: `Authentication required (login first)` })
        }


        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

        const user = await User.findById(decoded.userId);

        if (!user) {
            return res.status(401).json({ message: "user not found" })
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ message: `Invalid token ${error}` })
    }


}