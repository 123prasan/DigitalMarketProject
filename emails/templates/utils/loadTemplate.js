// emails/utils/loadTemplate.js
const fs = require('fs');
const path = require('path');

function loadTemplate(templatePath) {
  return fs.readFileSync(path.join(__dirname, '..', templatePath), 'utf-8');
}

module.exports = loadTemplate;
