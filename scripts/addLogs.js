const logger = require('../webintelx-backend/utils/logger');
logger.info(module, 'module loaded');
#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const backendUtilsDir = path.join(root, 'webintelx-backend', 'utils');
const loggerFile = path.join(backendUtilsDir, 'logger.js');

function findJS(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  for (let file of list) {
    const full = path.join(dir, file);
    if (fs.statSync(full).isDirectory()) {
      results = results.concat(findJS(full));
    } else if (file.endsWith('.js')) {
      if (path.resolve(full) === path.resolve(loggerFile)) continue;
      results.push(full);
    }
  }
  return results;
}

const files = findJS(root);

files.forEach((file) => {
  let content = fs.readFileSync(file, 'utf8');
  if (content.includes("require('" ) && content.includes('logger')) {
    // already has a require for logger; skip or ensure log
  }
  // compute relative require path
  const rel = path.relative(path.dirname(file), loggerFile).replace(/\\/g, '/');
  let requirePath = rel;
  if (!requirePath.startsWith('.') && !requirePath.startsWith('/')) {
    requirePath = './' + requirePath;
  }
  requirePath = requirePath.replace(/\.js$/,'');

  const importLine = `const logger = require('${requirePath}');`;
  const logLine = `logger.info(module, 'module loaded');`;

  // if import already present, just ensure log line is there
  if (content.includes(importLine)) {
    if (!content.includes(logLine)) {
      content = content.replace(importLine, importLine + '\n' + logLine);
    }
  } else {
    content = importLine + '\n' + logLine + '\n' + content;
  }

  fs.writeFileSync(file, content, 'utf8');
  console.log('Instrumented', file);
});

console.log('Logging instrumentation complete.');