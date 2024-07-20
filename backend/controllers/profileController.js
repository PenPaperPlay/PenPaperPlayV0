import { User } from "../database/models/users.js";
import bcryptjs from "bcryptjs"

export const getUser = async (req, res) => {
    const user = req.user;

    // Exclude the 'password' field from the user object
    const { password, ...userData } = user._doc; // Extracts all properties except 'password'

    res.status(200).json({ user: userData });
};

export const updateUserProfile = async (req, res) => {
    try {
        const { name, email, password, contactNumber } = req.body;
        const userIdForUpdate = req.params.id;

        if (req.user._id.toString() !== userIdForUpdate) {
            return res.status(403).json({ message: "You are not authorized to update this profile" });
        }

        const user = await User.findById(userIdForUpdate);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if (email && email !== user.email) {
            const existingEmail = await User.findOne({ email });
            if (existingEmail) {
                return res.status(400).json({ message: "Email is already in use by another user" });
            }
        }

        if (password) {
            const hashPassword = bcryptjs.hashSync(password, 10);
            user.password = hashPassword;
        }

        // Update only the fields that are provided in the request body
        user.name = name || user.name;
        user.email = email || user.email;
        user.contactNumber = contactNumber || user.contactNumber;

        const updatedUserProfile = await user.save();

        const fullUserinfo = await User.findById(userIdForUpdate)
        // Omit password from the response
        const { password: hashPassword, ...rest } = fullUserinfo._doc;

        res.status(200).json({ message: "Profile updated successfully", user: rest });
    } catch (error) {
        res.status(500).json({ message: "Profile update failed", error: error.message });
    }
};
