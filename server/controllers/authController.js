import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodeMailer.js";

// ================== REGISTER ====================
export const register = async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.json({ success: false, message: "Missing required fields" });
  }

  try {
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new userModel({
      username,
      email,
      password: hashedPassword,
    });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // sending welcome email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: newUser.email,  
      subject: "Account Successfully Created",
      html: `
        <h2>Hello ${newUser.username},</h2>   <!-- ✅ Corrected -->
        <p>We're thrilled to have you on board! 🎉</p>
        <p>Your account has been successfully created with the email: ${newUser.email}</p>
        <p>You’re now part of a growing community that values innovation, connection, and excellence. Here's what you can do next:</p>
        <br/>
        ✅ Explore your dashboard <br/>
        ✅ Update your profile <br/>
        ✅ Get started with our features <br/>
        <br/>
        If you have any questions or need assistance, our support team is just a click away.
      `,
    };

    await transporter.sendMail(mailOptions);

    return res.json({
      success: true,
      message: "Registration successful",
      userId: newUser._id,
    });

  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};


// ================== LOGIN ==================
export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({
      success: false,
      message: "Email and password are required",
    });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "Invalid email" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: "Invalid password" });
    }

    // ✅ Token generate tabhi hoga jab password sahi ho
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

  //   return res.json({ success: true, message: "Login successful" });
  // } catch (error) {
  //   return res.json({ success: false, message: error.message });
  // }
      // 🔹 yaha return me token aur userId bhejna hai
    return res.json({
      success: true,
      message: "Login successful",
      token,          // ⬅️ testing ke liye add kiya
      userId: user._id,
    });

  } catch (error) {
    return res.json({ success: false, message: error.message });
  }

};
// ================== LOGOUT ==================

export const logout = (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });
    return res.json({ success: true, message: "Logout successful" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// ======== Send verification OTP to the user email ===========

export const sendVerifyOtp = async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await userModel.findById(userId);

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    if (user.isAccountVerified) {
      return res.json({
        success: false,
        message: "Account is already verified",
      });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    // Encrypt OTP before saving
    const hashedOtp = await bcrypt.hash(otp, 10);

    user.verifyOtp = hashedOtp;
    user.verifyOtpExpireAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    // user se username aur email nikalna
    const { username, email } = user;

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Your Verification OTP",
      text: `Hello ${username},
      Your account has been successfully created with the email: ${email}

      To verify your account, please use the OTP below:

Your OTP for account verification is: ${otp}
This OTP is valid for 10 minutes. Do not share it with anyone.
Thank you for joining us!
– The webdesire Team`,

    };

    await transporter.sendMail(mailOptions);

    res.json({ success: true, message: "OTP sent to email" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};



// ======== verifyEmailOtp  ===========

export const verifyEmail = async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.json({ success: false, message: "Missing Details" });
  }

  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    // check if OTP expired
    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP has expired" });
    }

    // check if OTP matches (using bcrypt)
    const isMatch = await bcrypt.compare(otp, user.verifyOtp);
    if (!isMatch) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    // mark user as verified
    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;

    await user.save();

    return res.json({
      success: true,
      message: "Account verified successfully",
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};


// Check if user is authenticated

export const isAuthenticated = async (req, res) => {
  try {
    return res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

//send password reset otp

export const sendResetOtp = async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.json({ success: false, message: "Email is required" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Reset OTP",
      text: `Your OTP for reset password is ${otp}. It is valid for 10 minutes. Do not share it with anyone.`,
    };

    await transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "OTP sent to email" });

  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// Reset  user password

export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.json({ success: false, message: "Email, OTP and new password are required" });
  }
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    // ✅ Use correct DB field name
   if (user.resetOtp === "" || user.resetOtp !== String(otp)) {
    return res.json({ success: false, message: "Invalid OTP" });
}

    if (user.resetOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP has expired" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Clear OTP
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;

    await user.save();
    return res.json({ success: true, message: "Password reset successful" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

