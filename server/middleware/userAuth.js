import jwt from "jsonwebtoken";

const userAuth = (req, res, next) => {
  let token = req.cookies.token;

  if (!token && req.headers.authorization) {
    token = req.headers.authorization.split(" ")[1];
  }

  console.log(" Token received:", token);

  if (!token) {
    return res.json({ success: false, message: "Not Authorized, Login Again" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(" Decoded token:", decoded);

    const userId = decoded.id || decoded.userId;
    if (!userId) {
      return res.json({ success: false, message: "Token is not valid, Login Again" });
    }

    req.userId = userId;

    next();
  } catch (error) {
    console.log(" JWT Error:", error.message);
    return res.json({ success: false, message: "Token is not valid, Login Again" });
  }
};

export default userAuth;
