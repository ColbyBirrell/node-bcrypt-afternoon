const bcrypt = require("bcryptjs");

module.exports = {
  register: async (req, res) => {
    let { username, password, isAdmin } = req.body;
    let db = req.app.get("db");

    let result = await db.get_user(username);
    let existingUser = result[0];

    if (existingUser) {
      return res.status(409).send("username taken");
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const registeredUser = await db.register_user([isAdmin, username, hash]);
    let user = registeredUser[0];
    // console.log(user);
    req.session.user = {
      isAdmin: user.is_admin,
      id: user.id,
      username: user.username
    };

    return res.status(201).send(req.session.user);
  },

  login: async (req, res) => {
    let { username, password } = req.body;
    let db = req.app.get("db");

    let foundUser = await db.get_user(username);
    let user = foundUser[0];

    if (!user) {
      return res
        .status(401)
        .send("User not found. please register as a new user");
    }

    const isAuthenticated = bcrypt.compareSync(password, user.hash);
    if (!isAuthenticated) {
      return res.status(403).send("incorrect password");
    }
    req.session.user = {
      isAdmin: user.is_admin,
      id: user.id,
      username: user.username
    };

    return res.status(200).send(req.session.user);
  },

  logout: async (req, res) => {
    req.session.destroy();
    return res.sendStatus(200);
  }
};
