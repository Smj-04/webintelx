const express = require("express");
const router = express.Router();
const { checkEmailRep } = require("../controllers/emailRepController");

router.post("/emailrep", checkEmailRep);

module.exports = router;
