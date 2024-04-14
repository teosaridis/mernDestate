import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import prisma from "../lib/prisma.js";

export const register = async (req, res) => {
  const { username, email, password } = req.body;
  try {
    //Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user and save to db
    const newUser = await prisma.user.create({
      data: { username, email, password: hashedPassword },
    });
    console.log(newUser);

    res.status(201).json({ message: "User created successfully!" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Failed to create user!" });
  }
};

export const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { username },
    });
    if (!user) return res.status(401).json({ message: "Invalid credencials!" });
    // Check if password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ message: "Invalid credencials!" });
    // Generate cookie token and send to the user
    // res.setHeader("Set-Cookie", "mernEstate=" + "myValue").json("Success!");

    // age = (1 milisecond * 60) = 1 minute * 60 = 1 hour * 24 = 1 day * 7 = 1 week
    const cookieAge = 1000 * 60 * 60 * 24 * 7;

    const token = jwt.sign(
      {
        id: user.id,
      },
      process.env.JWT_SECRET_KEY,
      { expiresIn: cookieAge }
    );

    res
      .cookie("mernDestateToken", token, {
        httpOnly: true,
        // secure: true,
        maxAge: cookieAge,
      })
      .status(200)
      .json({ message: "Login successfully!" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Failed to login!" });
  }
};

export const logout = (req, res) => {
  res.clearCookie("mernDestateToken").status(200).json("Logout successfully!");
};
