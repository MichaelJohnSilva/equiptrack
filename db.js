// Database layer. EquipTrack stores its data in a Turso (hosted SQLite) database.
//   - On Render: set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN.
//   - On your own computer, with those two variables NOT set, it uses the local file borrow.db
//     (or the file in DB_FILE), exactly like before.
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');

const url = process.env.TURSO_DATABASE_URL || 'file:' + (process.env.DB_FILE || 'borrow.db');
const client = createClient({ url, authToken: process.env.TURSO_AUTH_TOKEN || undefined });

const clean = args => args.map(a => (a === undefined ? null : a));
const toObj = (rs, row) => {
  const o = {};
  rs.columns.forEach((c, i) => { const v = row[i]; o[c] = typeof v === 'bigint' ? Number(v) : v; });
  return o;
};

// Small helpers that keep the same shape as before: all() = list of rows, get() = first row,
// run() = { changes, lastInsertRowid }. Every one of them is async, so use await.
const db = {
  client,
  url,
  async all(sql, ...args) {
    const rs = await client.execute({ sql, args: clean(args) });
    return rs.rows.map(r => toObj(rs, r));
  },
  async get(sql, ...args) { return (await db.all(sql, ...args))[0]; },
  async run(sql, ...args) {
    const rs = await client.execute({ sql, args: clean(args) });
    return { changes: rs.rowsAffected, lastInsertRowid: rs.lastInsertRowid == null ? null : Number(rs.lastInsertRowid) };
  },
  async exec(sql) { await client.executeMultiple(sql); },
  async columns(table) { return (await db.all(`select name from pragma_table_info('${table}')`)).map(c => c.name); }
};

// The default department. Anything without a department lands here.
const DEFAULT_DEPT = 'College of Computer Studies';

// Creates the tables and adds any missing columns. Safe to run every time the server starts.
async function initSchema() {
  await db.exec(`
create table if not exists users(
  id integer primary key, name text not null, id_number text unique not null, hash text not null,
  role text not null check(role in ('student','faculty','lab','admin')));
create table if not exists equipment(
  id integer primary key, name text not null, category text not null default 'General',
  qty integer not null check(qty >= 0));
create table if not exists requests(
  id integer primary key,
  equipment_id integer not null references equipment(id) on delete cascade,
  user_id integer not null references users(id),
  qty integer not null check(qty >= 1),
  type text not null check(type in ('borrow','reserve')),
  date_from text not null, date_to text not null, purpose text not null,
  status text not null default 'Pending'
    check(status in ('Pending','Forwarded','Approved','Rejected','Returned','Cancelled')),
  forwarded_by integer references users(id),
  reviewed_by integer references users(id),
  created_at text default current_timestamp);
create table if not exists departments(id integer primary key, name text unique not null);
`);

  // Stop with a clear message if the database is from an older version.
  const cols = await db.columns('requests');
  if (!cols.includes('forwarded_by')) {
    console.error('\nThe database is from an older version.\nUse a new, empty database (or delete borrow.db when running locally), then start again.\n');
    process.exit(1);
  }

  // Add the return, penalty, receipt, damaged and repaired columns to older databases.
  const NEW_COLS = { return_condition: 'text', return_notes: 'text', returned_at: 'text',
    penalty_amount: 'real', penalty_note: 'text', penalty_status: 'text', penalized_by: 'integer',
    receipt_no: 'text', paid_at: 'text',
    return_confirmed_by: 'integer', return_confirmed_at: 'text',
    damaged_qty: 'integer',
    repaired_qty: 'integer', repaired_at: 'text', repaired_by: 'integer' };
  for (const [c, t] of Object.entries(NEW_COLS))
    if (!cols.includes(c)) await db.run(`alter table requests add column ${c} ${t}`);

  for (const tbl of ['users', 'equipment'])
    if (!(await db.columns(tbl)).includes('department_id'))
      await db.run(`alter table ${tbl} add column department_id integer`);
}

// First run: create an admin account and sample equipment. Then tidy up the departments.
// Each step can be repeated safely, so it is fine to run on every start.
async function bootstrap() {
  if (!(await db.get('select 1 as x from users'))) {
    await db.run('insert into users(name,id_number,hash,role) values(?,?,?,?)',
      'Administrator', process.env.ADMIN_ID || 'ADMIN',
      bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10), 'admin');
    for (const r of [['Compound microscope', 'Biology', 6], ['Digital oscilloscope', 'Electronics', 4],
      ['Laptop', 'IT', 10], ['Projector', 'AV', 3]])
      await db.run('insert into equipment(name,category,qty) values(?,?,?)', ...r);
  }

  // 1. Merge departments whose names differ only by upper/lower case.
  //    The one that is not spelled exactly like DEFAULT_DEPT is kept (then the oldest one).
  const groups = {};
  for (const d of await db.all('select id, name from departments order by id')) {
    const k = d.name.trim().toLowerCase();
    groups[k] = groups[k] || [];
    groups[k].push(d);
  }
  for (const g of Object.values(groups)) {
    if (g.length < 2) continue;
    g.sort((a, b) => (a.name === DEFAULT_DEPT) - (b.name === DEFAULT_DEPT) || a.id - b.id);
    const main = g[0];
    for (const d of g.slice(1)) {
      await db.run('update equipment set department_id=? where department_id=?', main.id, d.id);
      await db.run('update users set department_id=? where department_id=?', main.id, d.id);
      await db.run('delete from departments where id=?', d.id);
      console.log('Merged the duplicate department "' + d.name + '" into "' + main.name + '".');
    }
  }
  // 2. Make sure the default department exists (ignoring capital letters).
  let row = await db.get('select id from departments where lower(name)=lower(?)', DEFAULT_DEPT);
  if (!row) {
    await db.run('insert into departments(name) values(?)', DEFAULT_DEPT);
    row = await db.get('select id from departments where lower(name)=lower(?)', DEFAULT_DEPT);
  }
  const ccs = row.id;
  // 3. The old "General" department is removed. Its equipment and accounts move to the default one.
  const gen = await db.get("select id from departments where name='General'");
  if (gen) {
    await db.run('update equipment set department_id=? where department_id=?', ccs, gen.id);
    await db.run('update users set department_id=? where department_id=?', ccs, gen.id);
    await db.run('delete from departments where id=?', gen.id);
    console.log('The General department was removed. Its data moved to the default department.');
  }
  await db.run('update equipment set department_id=? where department_id is null', ccs);
  await db.run("update users set department_id=? where role='lab' and department_id is null", ccs);
}

module.exports = { db, initSchema, bootstrap, DEFAULT_DEPT };