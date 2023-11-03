const express = require("express")
const router = express.Router()
const User = require("../models/User")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

//REGISTER
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body
    // Check if the user with the given email already exists
    const existingUser = await User.findOne({ email })

    if (existingUser) {
      return res.status(400).json("Email is already registered!")
    }
    // Hash the password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hashSync(password, salt)

    // Create a new user
    const newUser = new User({ username, email, password: hashedPassword })

    // Save the user to the database
    const savedUser = await newUser.save()

    // Generate a JWT token for the newly registered user
    const token = jwt.sign(
      {
        _id: savedUser._id,
        username: savedUser.username,
        email: savedUser.email,
      },
      process.env.SECRET,
      { expiresIn: "3d" }
    )

    res.status(200).json({ token })
  } catch (err) {
    res.status(500).json(err)
  }
})

//LOGIN
router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email })

    if (!user) {
      return res.status(404).json("User not found!")
    }
    const match = await bcrypt.compare(req.body.password, user.password)

    if (!match) {
      return res.status(401).json("Wrong credentials!")
    }
    const token = jwt.sign(
      { _id: user._id, username: user.username, email: user.email },
      process.env.SECRET,
      { expiresIn: "3d" }
    )
    const { password, ...info } = user._doc
    res.status(200).json({ token })
  } catch (err) {
    res.status(500).json(err)
  }
})

//LOGOUT
router.get("/logout", async (req, res) => {
  try {
    res.status(200).send("User logged out successfully!")
  } catch (err) {
    res.status(500).json(err)
  }
})

//REFETCH USER
router.get("/refetch", (req, res) => {
  const token = req.headers.authorization

  if (!token) {
    return res.status(401).json({ message: "No token provided" })
  }

  // Verify the JWT token
  jwt.verify(token.split(" ")[1], process.env.SECRET, {}, async (err, data) => {
    if (err) {
      return res.status(403).json({ message: "Token is not valid" })
    }

    // The user data is contained in the `data` object
    res.status(200).json(data)
  })
})

module.exports = router
