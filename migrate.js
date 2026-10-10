// Copies your local database (borrow.db) into the Turso database. Run it ONCE from your computer.
//
//   PowerShell:
//     $env:TURSO_DATABASE_URL="libsql://your-database.turso.io"
//     $env:TURSO_AUTH_TOKEN="your-token"
//     node migrate.js                  (copies borrow.db)
//     node migrate.js C:\path\other.db (copies another file)
//     node migrate.js --wipe           (first erases what is already in Turso, then copies)
//
// Your local file is only read. It is never changed.
const { createClient } = require('@libsql/client');
const { db, initSchema } = require('./db');

if (!process.env.TURSO_DATABASE_URL) {
  console.error('Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN first (see the top of this file).');
  process.exit(1);
}
const wipe = process.argv.includes('--wipe');
const file = process.argv.slice(2).find(a => !a.startsWith('--')) || 'borrow.db';
const local = createClient({ url: 'file:' + file });

(async () => {
  await initSchema();                       // creates the tables in Turso
  const have = await db.get('select count(*) n from users');
  if (have.n > 0 && !wipe) {
    console.error('The Turso database already has ' + have.n + ' account(s).\nRun again with --wipe to erase it first, then copy your local data.');
    process.exit(1);
  }
  if (wipe) {
    for (const t of ['requests', 'equipment', 'users', 'departments']) await db.run('delete from ' + t);
    console.log('Erased the existing data in Turso.');
  }
  // Parents first, so every row finds the row it points to.
  for (const t of ['departments', 'users', 'equipment', 'requests']) {
    let src;
    try { src = await local.execute('select * from ' + t); }
    catch (e) { console.log(t + ': not found in ' + file + ', skipped.'); continue; }
    const remoteCols = await db.columns(t);
    const cols = src.columns.filter(c => remoteCols.includes(c));
    const sql = `insert into ${t}(${cols.join(',')}) values(${cols.map(() => '?').join(',')})`;
    const stmts = src.rows.map(r => ({ sql, args: cols.map(c => { const v = r[src.columns.indexOf(c)]; return v === undefined ? null : v; }) }));
    for (let i = 0; i < stmts.length; i += 50) await db.client.batch(stmts.slice(i, i + 50), 'write');
    console.log(t + ': copied ' + stmts.length + ' row(s).');
  }
  console.log('\nDone. Your data is now in Turso.');
  process.exit(0);
})().catch(e => { console.error('Failed: ' + e.message); process.exit(1); });