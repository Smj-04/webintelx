const express = require("express");
const router = express.Router();
const { scanTokenAuth } = require("../controllers/tokenAuthController");

router.post("/token-auth", scanTokenAuth);

module.exports = router;
