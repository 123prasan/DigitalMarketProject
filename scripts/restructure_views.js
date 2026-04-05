const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const viewsRoot = path.join(root, 'views');
const jsFiles = [
  path.join(root, 'server.js'),
  path.join(root, 'routes', 'authentication', 'googleAuth.js'),
  path.join(root, 'routes', 'chatRoutes.js'),
  path.join(root, 'routes', 'Adanalytics.js'),
];

const replacements = [
  ['res.render(\'login\'', 'res.render(\'auth/login\''],
  ['res.render("login"', 'res.render("auth/login"'],
  ['res.render(\'user-login.ejs\'', 'res.render(\'auth/user-login\''],
  ['res.render("user-login.ejs"', 'res.render("auth/user-login"'],
  ['res.render(\'emailVerified.ejs\'', 'res.render(\'auth/emailVerified\''],
  ['res.render("emailVerified.ejs"', 'res.render("auth/emailVerified"'],
  ['res.render(\'resetpass.ejs\'', 'res.render(\'auth/resetpass\''],
  ['res.render("resetpass.ejs"', 'res.render("auth/resetpass"'],

  ['res.render(\'privacy-policy\'', 'res.render(\'pages/privacy-policy\''],
  ['res.render("privacy-policy"', 'res.render("pages/privacy-policy"'],
  ['res.render(\'refundpolicy\'', 'res.render(\'pages/refundpolicy\''],
  ['res.render("refundpolicy"', 'res.render("pages/refundpolicy"'],
  ['res.render(\'terms&conditions\'', 'res.render(\'pages/terms&conditions\''],
  ['res.render("terms&conditions"', 'res.render("pages/terms&conditions"'],
  ['res.render(\'contact\'', 'res.render(\'pages/contact\''],
  ['res.render("contact"', 'res.render("pages/contact"'],
  ['res.render(\'acceptable-use\'', 'res.render(\'pages/acceptable-use\''],
  ['res.render("acceptable-use"', 'res.render("pages/acceptable-use"'],
  ['res.render(\'return-cancellation\'', 'res.render(\'pages/return-cancellation\''],
  ['res.render("return-cancellation"', 'res.render("pages/return-cancellation"'],
  ['res.render(\'intellectual-property\'', 'res.render(\'pages/intellectual-property\''],
  ['res.render("intellectual-property"', 'res.render("pages/intellectual-property"'],
  ['res.render(\'help.ejs\'', 'res.render(\'pages/help\''],
  ['res.render("help.ejs"', 'res.render("pages/help"'],
  ['res.render(\'dashboardhelp.ejs\'', 'res.render(\'dashboard/dashboardhelp\''],
  ['res.render("dashboardhelp.ejs"', 'res.render("dashboard/dashboardhelp"'],

  ['res.render(\'file-not-found\'', 'res.render(\'files/file-not-found\''],
  ['res.render("file-not-found"', 'res.render("files/file-not-found"'],
  ['res.render(\'file-details\'', 'res.render(\'files/file-details\''],
  ['res.render("file-details"', 'res.render("files/file-details"'],
  ['res.render(\'file-preview\'', 'res.render(\'files/file-preview\''],
  ['res.render("file-preview"', 'res.render("files/file-preview"'],
  ['res.render(\'relatedfiles\'', 'res.render(\'files/relatedfiles\''],
  ['res.render("relatedfiles"', 'res.render("files/relatedfiles"'],

  ['res.render(\'checkout\'', 'res.render(\'commerce/checkout\''],
  ['res.render("checkout"', 'res.render("commerce/checkout"'],
  ['res.render(\'payment-success\'', 'res.render(\'commerce/payment-success\''],
  ['res.render("payment-success"', 'res.render("commerce/payment-success"'],
  ['res.render(\'payment-failure\'', 'res.render(\'commerce/payment-failure\''],
  ['res.render("payment-failure"', 'res.render("commerce/payment-failure"'],
  ['res.render(\'pricing\'', 'res.render(\'commerce/pricing\''],
  ['res.render("pricing"', 'res.render("commerce/pricing"'],
  ['res.render(\'subscription\'', 'res.render(\'commerce/subscription\''],
  ['res.render("subscription"', 'res.render("commerce/subscription"'],

  ['res.render(\'index\'', 'res.render(\'pages/index\''],
  ['res.render("index"', 'res.render("pages/index"'],

  ['res.render(\'courses\'', 'res.render(\'courses/courses\''],
  ['res.render("courses"', 'res.render("courses/courses"'],
  ['res.render(\'course-detail\'', 'res.render(\'courses/course-detail\''],
  ['res.render("course-detail"', 'res.render("courses/course-detail"'],
  ['res.render(\'courseplayer\'', 'res.render(\'courses/courseplayer\''],
  ['res.render("courseplayer"', 'res.render("courses/courseplayer"'],
  ['res.render(\'createcourse\'', 'res.render(\'courses/createcourse\''],
  ['res.render("createcourse"', 'res.render("courses/createcourse"'],
  ['res.render(\'edit-course\'', 'res.render(\'courses/edit-course\''],
  ['res.render("edit-course"', 'res.render("courses/edit-course"'],
  ['res.render(\'my-courses\'', 'res.render(\'courses/my-courses\''],
  ['res.render("my-courses"', 'res.render("courses/my-courses"'],

  ['res.render(\'notifications\'', 'res.render(\'dashboard/notifications\''],
  ['res.render("notifications"', 'res.render("dashboard/notifications"'],
  ['res.render(\'mydownloads\'', 'res.render(\'dashboard/mydownloads\''],
  ['res.render("mydownloads"', 'res.render("dashboard/mydownloads"'],
  ['res.render(\'myprofile\'', 'res.render(\'dashboard/myprofile\''],
  ['res.render("myprofile"', 'res.render("dashboard/myprofile"'],
  ['res.render(\'following\'', 'res.render(\'dashboard/following\''],
  ['res.render("following"', 'res.render("dashboard/following"'],
  ['res.render(\'followers\'', 'res.render(\'dashboard/followers\''],
  ['res.render("followers"', 'res.render("dashboard/followers"'],
  ['res.render(\'perchasehistory\'', 'res.render(\'dashboard/perchasehistory\''],
  ['res.render("perchasehistory"', 'res.render("dashboard/perchasehistory"'],
  ['res.render(\'dashboardhelp\'', 'res.render(\'dashboard/dashboardhelp\''],
  ['res.render("dashboardhelp"', 'res.render("dashboard/dashboardhelp"'],
  ['res.render(\'profileNotfound\'', 'res.render(\'dashboard/profileNotFound\''],
  ['res.render("profileNotfound"', 'res.render("dashboard/profileNotFound"'],
  ['res.render(\'publicprofile\'', 'res.render(\'dashboard/publicprofile\''],
  ['res.render("publicprofile"', 'res.render("dashboard/publicprofile"'],

  ['res.render(\'wishlist.ejs\'', 'res.render(\'search/wishlist\''],
  ['res.render("wishlist.ejs"', 'res.render("search/wishlist"'],

  ['res.render(\'analytics\'', 'res.render(\'admin/analytics\''],
  ['res.render("analytics"', 'res.render("admin/analytics"'],
  ['res.render(\'admin\'', 'res.render(\'admin/admin\''],
  ['res.render("admin"', 'res.render("admin/admin"'],
];

function replaceContent(file, replacements) {
  let content = fs.readFileSync(file, 'utf8');
  let changed = false;
  replacements.forEach(([from, to]) => {
    if (content.includes(from)) {
      content = content.split(from).join(to);
      changed = true;
    }
  });
  if (changed) {
    fs.writeFileSync(file, content, 'utf8');
    console.log(`Patched ${file}`);
  }
}

jsFiles.forEach((file) => {
  if (fs.existsSync(file)) {
    replaceContent(file, replacements);
  } else {
    console.warn(`Missing file: ${file}`);
  }
});

function walk(dir) {
  let results = [];
  const list = fs.readdirSync(dir, { withFileTypes: true });
  list.forEach((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results = results.concat(walk(fullPath));
    } else if (entry.isFile() && fullPath.endsWith('.ejs')) {
      results.push(fullPath);
    }
  });
  return results;
}

const ejsFiles = walk(viewsRoot);
const includeReplacements = [
  [/<%-\s*include\(\s*['\"]header['\"]\s*\)\s*%>/g, '<%- include("../components/header") %>'],
  [/<%-\s*include\(\s*['\"]footer['\"]\s*\)\s*%>/g, '<%- include("../components/footer") %>'],
];

let updatedCount = 0;
ejsFiles.forEach((file) => {
  let content = fs.readFileSync(file, 'utf8');
  let changed = false;
  includeReplacements.forEach(([regex, replacement]) => {
    if (regex.test(content)) {
      content = content.replace(regex, replacement);
      changed = true;
    }
  });
  if (file.endsWith(path.join('courses', 'createcourse.ejs'))) {
    const fileUploadRegex = /<%-\s*include\(\s*['\"]fileupload['\"]\s*\)\s*%>/g;
    if (fileUploadRegex.test(content)) {
      content = content.replace(fileUploadRegex, '<%- include("../files/fileupload") %>');
      changed = true;
    }
  }
  if (changed) {
    fs.writeFileSync(file, content, 'utf8');
    updatedCount += 1;
    console.log(`Updated includes in ${file}`);
  }
});

console.log(`Done. Updated ${updatedCount} EJS files.`);
