const { Router } = require("express");
const router = new Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const { check, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const config = require("config");

//api/auth/register
router.post(
  "/register",
  [
    check("email", "Incorrect email").isEmail(),
    check("password", "Min length of password is 6 symbols").isLength({
      min: 6,
    }),
  ],
  async (req, res) => {
    console.log("Body");
    console.log(req.body);

    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Incorrect data while registration",
        });
      }

      const { email, password } = req.body;
      const candidate = await User.findOne({ email });

      if (candidate) {
        return res.status(400).json({ message: "User is already exist" });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const user = new User({ email, password: hashedPassword });

      await user.save();

      res.status(201).json({ message: "User has been successfully created" });
    } catch (e) {
      res
        .status(500)
        .json({ message: "Something went wrong. Please try again later" });
    }
  }
);

//api/auth/login
router.post(
  "/login",
  [
    check("email", "Enter the correct email").normalizeEmail().isEmail(),
    check("password", "Enter the password").exists(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Incorrect data while registration",
        });
      }

      const { email, password } = req.body;
      const user = await User.findOne({ email });

      if (!user) return res.status(500).json({ message: "User was not found" });

      const isMatch = bcrypt.compare(password, user.password);

      if (!isMatch)
        return res.status(400).json({ message: "The password is incorrect" });

      const token = jwt.sign({ userId: user.id }, config.get("jwtSecret"), {
        expiresIn: "1h",
      });

      res.json({ token, userId: user.id });
    } catch (e) {
      res
        .status(500)
        .json({ message: "Something went wrong. Please try again later" });
    }
  }
);

module.exports = router;
