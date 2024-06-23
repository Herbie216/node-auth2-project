const router = require("express").Router();
const Users = require("./users-model.js");
const { restricted, only } = require("../auth/auth-middleware.js");

router.get("/", restricted, async (req, res, next) => { 
  try {
    const users = await Users.find();
    res.json(users);
  } catch (err) {
    next(err);
  }
});

router.get("/:user_id", restricted, only('admin'), (req, res, next) => { 
  Users.findById(req.params.user_id)
    .then(user => {
      res.json(user);
    })
    .catch(next);
});

module.exports = router;
