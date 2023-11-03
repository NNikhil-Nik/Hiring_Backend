const jwt = require("jsonwebtoken")

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization

  if (!authHeader) {
    return res.status(401).json({ message: "You are not authenticated!" })
  }

  const token = authHeader.split(" ")[1] // Assuming the token is in the format: "Bearer yourToken"

  jwt.verify(token, process.env.SECRET, async (err, data) => {
    if (err) {
      return res.status(403).json("Token is not valid!")
    }

    req.userId = data._id

    next()
  })
}

module.exports = verifyToken
