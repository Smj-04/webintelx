const express = require("express");
const router = express.Router();
const { scanIDOR } = require("../controllers/idorController");

router.post("/idor", scanIDOR);

module.exports = router;
