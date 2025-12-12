module.exports = function cleanUrl(input) {
  try {
    // If input is something like "http://site.com/path"
    // force URL parsing by adding protocol if missing
    if (!input.startsWith("http://") && !input.startsWith("https://")) {
      input = "http://" + input;
    }

    const url = new URL(input);
    return url.hostname; // hostname ONLY
  } catch (err) {
    // If parsing fails, return original best guess
    return input.replace(/https?:\/\//, "").split("/")[0];
  }
};
