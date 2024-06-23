const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); 
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const { role_name } = req;
    const hash = bcrypt.hashSync(password, 8);
    const newUser = await User.add({ username, password: hash, role_name });
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  const { user } = req;
  if (bcrypt.compareSync(password, user.password)) {
    const token = buildToken(user)
    res.json({
      message: `${user.username} is back`,
      token
    })
  } else {
    next({ status: 401, message: 'Invalid credentials' })
  }
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
