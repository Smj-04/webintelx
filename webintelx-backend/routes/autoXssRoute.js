const express = require("express");
const router = express.Router();

const {
  runAutoXSSScan,
} = require("../controllers/autoXssController");

router.post("/autoxss", runAutoXSSScan);

module.exports = router;
