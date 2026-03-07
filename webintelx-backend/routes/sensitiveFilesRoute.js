const express = require("express");
const router = express.Router();
const { scanSensitiveFiles } = require("../controllers/sensitiveFilesController");

router.post("/", scanSensitiveFiles);

module.exports = router;