const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const [, , emailArg, balanceArg] = process.argv;
if (!emailArg || !balanceArg) {
  console.log('Použití: node admin-balance-cli.js <email> <balance>');
  process.exit(1);
}

const email = String(emailArg).trim().toLowerCase();
const balance = Number(balanceArg);
if (!Number.isFinite(balance) || balance < 0) {
  console.error('Balance musí být číslo >= 0');
  process.exit(1);
}

const db = new sqlite3.Database(path.join(__dirname, 'otodrop.db'));
db.run('UPDATE users SET balance = ? WHERE lower(email) = ?', [balance, email], function onDone(err) {
  if (err) {
    console.error(err.message);
    process.exit(1);
  }
  if (this.changes === 0) {
    console.error('Uživatel nenalezen.');
    process.exit(1);
  }
  console.log(`OK: ${email} má nyní ${balance}`);
});
