const express = require("express");
const router = express.Router();
const { runPing } = require("../controllers/pingController");

router.post("/", runPing);

module.exports = router;
