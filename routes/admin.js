const express = require("express");
const User = require("../models/User");
const router = express.Router();

router.get("/users", adminOnly, async (req, res) => {
    try {
        const users = await User.find();

        res.render("users", {
            title: "All Users",
            users
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});

function adminOnly(req, res, next) {
  if (!req.session.authUserId || !req.session.isAdmin) {
    return res.redirect('/login');
  }
  next();
}

module.exports = router