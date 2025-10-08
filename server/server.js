import express from "express";
import "dotenv/config";
import cors from "cors";
import cookieParser from "cookie-parser";
import connectDB from "./config/db.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";

const app = express();
const PORT = process.env.PORT || 5000;

connectDB();

app.use(cors({
  origin: "http://localhost:5000",
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send("Hello from the API!");
});
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

