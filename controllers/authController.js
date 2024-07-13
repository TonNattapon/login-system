const User = require("../model/userSchema");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const createUser = async (req, res) => {
  try {
    //check if email already exist
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res
        .status(400)
        .json({ errors: { email: "Email already exists" } });
    }

    //create user in db
    const user = await User.create(req.body);

    //gen token
    const token = jwt.sign(
      { user: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    res.status(201).json({
      user: {
        id: user._id,
        email: user.email,
        password: user.password,
      },
      token,
    });
  } catch (err) {
    res.status(500).json({ message: "Signup failed" });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      const passwordMath = await bcrypt.compare(password, user.password);
      if (passwordMath) {
        const token = jwt.sign(
          { user: user._id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );
        res.status(201).json({
          user: {
            id: user._id,
            email: user.email,
            password: user.password,
          },
          token,
        });
      } else {
        return res.status(400).json({ message: "Incorrect password" });
      }
    } else {
      return res.status(400).json({ message: "No user found with this email" });
    }
  } catch (error) {
    res.status(500).json({ message: "Login failed" });
  }
};

module.exports = { createUser, loginUser };
