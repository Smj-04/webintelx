const emailRepCheck = require("../utils/emailRepCheck");
const hunterEmailFinder = require("../utils/hunterEmailFinder");
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

exports.checkEmailRep = async (req, res) => {
  const { email, url } = req.body;

  // Case 1: direct email
  if (email) {
    const result = await emailRepCheck(email);
    return res.json({ module: "Email Reputation", email, ...result });
  }

  // Case 2: URL → Hunter → EmailRep
  if (url) {
    const domain = url
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "");

    const hunter = await hunterEmailFinder(domain);

    if (!hunter.success || hunter.emails.length === 0) {
      return res.status(404).json({
        error: "No emails found via Hunter"
      });
    }

    const results = [];
    for (const foundEmail of hunter.emails) {
      const rep = await emailRepCheck(foundEmail);
      results.push({ email: foundEmail, ...rep });

      // ⏱️ avoid EmailRep rate limit
      await delay(1200);
    }


    return res.json({
      module: "Email Reputation",
      domain,
      total: results.length,
      results
    });
  }

  return res.status(400).json({
    error: "Email or URL required"
  });
};
