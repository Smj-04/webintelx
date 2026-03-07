const express = require("express");
const router = express.Router();
const { corsScan } = require("../controllers/corsController");

router.post("/", corsScan);

module.exports = router;