import jwt from "jsonwebtoken";
import mongoose, { Mongoose } from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true,},
  email: { type: String, required: true, unique: true }, 
  password: { type: String, required: true,},
  verifyOtp: { type: String,default: '' },
  verifyOtpExpireAt: { type: Number, default: 0 },
    isAccountVerified: { type: Boolean, default: false },
    resetOtp: { type: String, default: '' },
    resetOtpExpireAt: { type: Number, default: 0 },
});

const userModel = mongoose.models.user || mongoose.model("User", userSchema);

export default userModel;