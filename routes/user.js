const express = require("express");
const { signup, signin } = require("../controller/UserController");
const { userValidation } = require("../middleware/userValidation");
const router = express.Router();

router.post("/signup", userValidation, signup);

router.post("/signin", userValidation, signin);

module.exports = router;
