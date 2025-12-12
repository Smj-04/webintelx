const express = require("express");
const router = express.Router();
const { runWhois } = require("../controllers/whoisController");

router.post("/", runWhois);

module.exports = router;
