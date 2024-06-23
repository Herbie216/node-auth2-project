const { JWT_SECRET } = require("../secrets"); 
const { findBy } = require('../users/users-model')
const jwt = require('jsonwebtoken')

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) {
    return next({ status: 401, message: 'Token required' })
  } else {
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
      if (err) {
        next({ status: 401, message: 'Token invalid' })
      } else {
        req.decodedToken = decodedToken
        next()
      }
    })
  }
}

const only = role_name => (req, res, next) => {
  if (role_name === req.decodedToken.role_name) {
    next()
  } else {
    next({ status: 403, message: 'This is not for you' })
  }
}

const checkUsernameExists = async (req, res, next) => {
  try {
    const [user] = await findBy({ username: req.body.username })
    if (!user) {
      next({ status: 401, message: 'Invalid credentials' })
    } else {
      req.user = user
      next()
    }
  } catch (error) {
    next(error)
  }
}


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  if (!role_name || !role_name.trim()) {
    req.role_name = 'student';
  } else {
    req.role_name = role_name.trim();
  }
  
  if (req.role_name === 'admin') {
    next({ status: 422, message: "Role name can not be admin" });
  } else if (req.role_name.length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" });
  } else {
    next();
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
