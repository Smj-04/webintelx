const express = require("express");
const router = express.Router();
const { runSqlmap } = require("../controllers/sqlmapController");

router.post("/sqlmap", runSqlmap);
module.exports = router;
