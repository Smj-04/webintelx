const express = require("express");
const router = express.Router();
const { checkLeak } = require("../controllers/leakcheckController");

router.post("/leakcheck", checkLeak);

module.exports = router;
