const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const IGNORED = ['node_modules', '.git', 'dist', 'public', 'netlify'];
const patterns = [
  /SUPABASE_SERVICE_KEY/gi,
  /SUPABASE_ANON_KEY/gi,
  /VITE_SUPABASE_ANON_KEY/gi,
  /VITE_SUPABASE_URL/gi,
  /SMTP_PASS/gi,
  /SMTP_USER/gi,
  /EMAIL_TOKEN_SECRET/gi,
  /APP_URL/gi
];

function walk(dir, cb) {
  for (const name of fs.readdirSync(dir)) {
    if (IGNORED.includes(name)) continue;
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) walk(full, cb);
    else cb(full);
  }
}

const results = [];
walk(ROOT, (file) => {
  if (!file.match(/\.(js|ts|tsx|jsx|json|env|md|html)$/)) return;
  const content = fs.readFileSync(file, 'utf8');
  for (const p of patterns) {
    if (p.test(content)) results.push({ file, pattern: p.toString() });
  }
});

if (results.length === 0) {
  console.log('No suspicious secret keys found by name.');
  process.exit(0);
}
console.log('Potential leaks:');
for (const r of results) console.log(r.file, r.pattern);
process.exit(0);
