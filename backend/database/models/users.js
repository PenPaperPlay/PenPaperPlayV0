import mongoose from "mongoose";
import { UserRole } from "../../enums/user.enum.js";

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: [UserRole.PLAYER, UserRole.COACH], required: true },
});

export const User = mongoose.model("users", UserSchema);
