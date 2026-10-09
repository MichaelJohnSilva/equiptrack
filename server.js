const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'change-this-secret';
const db = new Database(process.env.DB_FILE || 'borrow.db');
db.pragma('foreign_keys = ON');

db.exec(`
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
`);

// Stop with a clear message if the database is from an older version.
const cols = db.prepare('pragma table_info(requests)').all().map(c => c.name);
if (!cols.includes('forwarded_by')) {
  console.error('\nThe database file is from an older version.\nStop the server, delete borrow.db, then run npm start again.\n');
  process.exit(1);
}

// Add the return, penalty and receipt columns to older databases (no need to delete borrow.db).
// damaged_qty  = how many of the returned units are damaged (empty on old records = all of them).
// repaired_qty = how many of those damaged units the admin marked as repaired or replaced.
const NEW_COLS = { return_condition: 'text', return_notes: 'text', returned_at: 'text',
  penalty_amount: 'real', penalty_note: 'text', penalty_status: 'text', penalized_by: 'integer',
  receipt_no: 'text', paid_at: 'text',
  return_confirmed_by: 'integer', return_confirmed_at: 'text',
  damaged_qty: 'integer',
  repaired_qty: 'integer', repaired_at: 'text', repaired_by: 'integer' };
for (const [c, t] of Object.entries(NEW_COLS))
  if (!cols.includes(c)) db.exec(`alter table requests add column ${c} ${t}`);

// First run: create an admin account and sample equipment.
if (!db.prepare('select 1 from users').get()) {
  db.prepare('insert into users(name,id_number,hash,role) values(?,?,?,?)').run(
    'Administrator', process.env.ADMIN_ID || 'ADMIN',
    bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10), 'admin');
  const ins = db.prepare('insert into equipment(name,category,qty) values(?,?,?)');
  [['Compound microscope', 'Biology', 6], ['Digital oscilloscope', 'Electronics', 4],
   ['Laptop', 'IT', 10], ['Projector', 'AV', 3]].forEach(r => ins.run(...r));
}

// ---------- Departments ----------
// Every lab personnel account and every equipment item belongs to one department.
// Students and faculty also have an enrolled department (chosen when they register).
db.exec('create table if not exists departments(id integer primary key, name text unique not null)');
for (const tbl of ['users', 'equipment'])
  if (!db.prepare(`pragma table_info(${tbl})`).all().some(c => c.name === 'department_id'))
    db.exec(`alter table ${tbl} add column department_id integer`);

// The default department. Anything without a department lands here.
const DEFAULT_DEPT = 'College of Computer Studies';
db.transaction(() => {
  // 1. Merge departments whose names differ only by upper/lower case.
  //    The one that is not spelled exactly like DEFAULT_DEPT is kept (then the oldest one).
  const groups = {};
  for (const d of db.prepare('select id, name from departments order by id').all()) {
    const k = d.name.trim().toLowerCase();
    groups[k] = groups[k] || [];
    groups[k].push(d);
  }
  for (const g of Object.values(groups)) {
    if (g.length < 2) continue;
    g.sort((a, b) => (a.name === DEFAULT_DEPT) - (b.name === DEFAULT_DEPT) || a.id - b.id);
    const main = g[0];
    for (const d of g.slice(1)) {
      db.prepare('update equipment set department_id=? where department_id=?').run(main.id, d.id);
      db.prepare("update users set department_id=? where department_id=?").run(main.id, d.id);
      db.prepare('delete from departments where id=?').run(d.id);
      console.log('Merged the duplicate department "' + d.name + '" into "' + main.name + '".');
    }
  }
  // 2. Make sure the default department exists (ignoring capital letters).
  let row = db.prepare('select id from departments where lower(name)=lower(?)').get(DEFAULT_DEPT);
  if (!row) {
    db.prepare('insert into departments(name) values(?)').run(DEFAULT_DEPT);
    row = db.prepare('select id from departments where lower(name)=lower(?)').get(DEFAULT_DEPT);
  }
  const ccs = row.id;
  // 3. The old "General" department is removed. Its equipment and accounts move to the default one.
  const gen = db.prepare("select id from departments where name='General'").get();
  if (gen) {
    db.prepare('update equipment set department_id=? where department_id=?').run(ccs, gen.id);
    db.prepare("update users set department_id=? where department_id=?").run(ccs, gen.id);
    db.prepare('delete from departments where id=?').run(gen.id);
    console.log('The General department was removed. Its data moved to the default department.');
  }
  db.prepare('update equipment set department_id=? where department_id is null').run(ccs);
  db.prepare("update users set department_id=? where role='lab' and department_id is null").run(ccs);
})();
const deptExists = id => Number.isInteger(Number(id)) && !!db.prepare('select 1 from departments where id=?').get(Number(id));

// Who reviews whose requests.
const REVIEWS = { lab: ['student', 'faculty'], admin: ['student', 'faculty'] };
// Prints what happens to the terminal. Passwords are never logged.
const log = m => console.log('[' + new Date().toLocaleTimeString() + '] ' + m);
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '');

// Units of an item that are damaged and NOT yet repaired or replaced. They are not available.
// For each damaged return: damaged units minus the units the admin marked as repaired or replaced.
function damagedUnits(equipmentId) {
  return db.prepare(`select coalesce(sum(coalesce(damaged_qty, qty) - coalesce(repaired_qty, 0)),0) n from requests
    where equipment_id=? and return_condition='Damaged'`).get(equipmentId).n;
}

// Every damaged return of an item (used by the Inventory cards of the admin and lab personnel).
function damagedList(equipmentId) {
  return db.prepare(`select r.id, r.qty, coalesce(r.damaged_qty, r.qty) damaged_qty,
      coalesce(r.repaired_qty, 0) repaired_qty, r.returned_at, r.return_notes, r.repaired_at,
      u.name requester, u.id_number
    from requests r join users u on u.id=r.user_id
    where r.equipment_id=? and r.return_condition='Damaged' order by r.id desc`).all(equipmentId);
}

// Available = total, minus what is out on approved loans for those dates, minus the damaged units
// that are still not repaired or replaced.
function available(equipmentId, from, to) {
  const e = db.prepare('select qty from equipment where id=?').get(equipmentId);
  if (!e) return null;
  const used = db.prepare(`select coalesce(sum(qty),0) n from requests
    where equipment_id=? and status='Approved' and date_from<=? and date_to>=?`).get(equipmentId, to, from).n;
  return e.qty - used - damagedUnits(equipmentId);
}

// Checks the sign-in token, and that the user still exists in the database.
const auth = (req, res, next) => {
  try {
    const t = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    const u = db.prepare('select id, name, role, department_id from users where id=?').get(t.id);
    if (!u) throw new Error('user no longer exists');
    req.user = { id: u.id, name: u.name, role: u.role, department_id: u.department_id };
    next();
  } catch { res.status(401).json({ error: 'Please sign in.' }); }
};
const only = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Not allowed for your role.' });

const app = express();
const rateLimit = require('express-rate-limit');
// Render sits behind a proxy. Without this, every visitor looks like the same IP
// and the limit below would block everyone at once.
app.set('trust proxy', 1);
const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  message: { error: 'Too many sign-in attempts. Try again in 15 minutes.' }
});
// Render uses this to check that the server is running.
app.get('/health', (req, res) => res.send('ok'));
app.use(express.json());
app.use(express.static('public'));

const token = u => jwt.sign({ id: u.id, name: u.name, role: u.role }, SECRET, { expiresIn: '8h' });
const deptName = id => { const d = id ? db.prepare('select name from departments where id=?').get(id) : null; return d ? d.name : null; };

// ---------- Accounts ----------
// ID number rules. Change these patterns if your school uses different formats.
const ID_RULES = {
  student: { re: /^\d{7,10}$/, msg: 'Student ID number must be 7 to 10 digits, for example 20231234.' },
  faculty: { re: /^FAC-\d{4,6}$/, msg: 'Faculty ID number must look like FAC-12345.' },
  lab:     { re: /^[A-Z0-9-]{3,20}$/, msg: 'ID number must be 3 to 20 letters, numbers or dashes.' },
  admin:   { re: /^[A-Z0-9-]{3,20}$/, msg: 'ID number must be 3 to 20 letters, numbers or dashes.' }
};
const cleanId = (role, raw) => {
  const s = String(raw || '').trim().toUpperCase();
  return role === 'student' ? s.replace(/[\s-]/g, '') : s.replace(/\s/g, '');
};
// Students, faculty and lab personnel must all have a department.
function createUser(res, { name, idNumber, password, role, departmentId }, allowed) {
  if (!name || !String(name).trim() || !password || password.length < 8)
    return res.status(400).json({ error: 'Name and a password of 8+ characters are required.' });
  if (!allowed.includes(role) || !ID_RULES[role]) return res.status(400).json({ error: 'Choose a valid role.' });
  const id = cleanId(role, idNumber);
  if (!ID_RULES[role].re.test(id)) return res.status(400).json({ error: ID_RULES[role].msg });
  if (role !== 'admin' && !deptExists(departmentId))
    return res.status(400).json({ error: role === 'lab'
      ? 'Choose the department of this laboratory personnel.'
      : 'Choose the department you are enrolled in.' });
  try {
    const dept = Number(departmentId);
    const r = db.prepare('insert into users(name,id_number,hash,role,department_id) values(?,?,?,?,?)')
      .run(String(name).trim(), id, bcrypt.hashSync(password, 10), role, dept);
    return { id: r.lastInsertRowid, name: String(name).trim(), role, department: deptName(dept) };
  } catch { return res.status(409).json({ error: 'That ID number is already registered.' }); }
}

// Students and faculty can sign up themselves. They choose their enrolled department.
app.post('/api/register', (req, res) => {
  const u = createUser(res, req.body, ['student', 'faculty']);
  if (u && u.id) {
    log(`NEW ACCOUNT   ${u.role}  ${cleanId(u.role, req.body.idNumber)}  ${u.name}  (${u.department})`);
    res.json({ token: token(u), name: u.name, role: u.role, department: u.department });
  }
});

// The admin can create student and faculty accounts. Lab personnel are added inside a department.
app.post('/api/users', auth, only('admin'), (req, res) => {
  const u = createUser(res, req.body, ['student', 'faculty']);
  if (u && u.id) {
    log(`ACCOUNT MADE BY ADMIN   ${u.role}  ${cleanId(u.role, req.body.idNumber)}  ${u.name}  (${u.department})`);
    res.json({ id: u.id });
  }
});

// The sign-in page needs the department names before anyone is signed in (names only, nothing private).
app.get('/api/public/departments', (req, res) =>
  res.json(db.prepare('select id, name from departments order by name').all()));

// Sign in. The page says which kind of account it is signing in as ("as"),
// and laboratory personnel must also choose their assigned department.
app.post('/api/login', loginLimit, (req, res) => {
  const raw = String(req.body.idNumber || '').trim().toUpperCase();
  const u = db.prepare('select * from users where id_number in (?,?)').get(raw.replace(/\s/g, ''), raw.replace(/[\s-]/g, ''));
  if (!u || !bcrypt.compareSync(req.body.password || '', u.hash)) {
    log(`SIGN IN FAILED   ${raw || '(empty)'}`);
    return res.status(401).json({ error: 'Wrong ID number or password.' });
  }
  const as = req.body.as;
  if (as && as !== u.role) {
    log(`SIGN IN REFUSED   ${raw}  chose ${as} but the account is ${u.role}`);
    return res.status(403).json({ error: 'This ID number belongs to a different type of account. Go back and choose the right one.' });
  }
  if (u.role === 'lab' && Number(req.body.departmentId) !== u.department_id) {
    log(`SIGN IN REFUSED   ${raw}  chose the wrong department`);
    return res.status(403).json({ error: 'You are not assigned to that department. Choose your own department.' });
  }
  log(`SIGN IN   ${u.role}  ${u.id_number}  ${u.name}`);
  res.json({ token: token(u), name: u.name, role: u.role, department: deptName(u.department_id) });
});

// Who is signed in, with their department. The page uses this for the header.
app.get('/api/me', auth, (req, res) =>
  res.json({ name: req.user.name, role: req.user.role,
    department: deptName(req.user.department_id), department_id: req.user.department_id }));

// ---------- Equipment ----------
// Admin sees everything. Everyone else (lab personnel, students, faculty) sees only the
// equipment of their own department. A student with no department sees nothing.
// "damaged" is the number of units that are damaged and not yet repaired or replaced.
// Admin and lab personnel also get the list of damaged returns (students and faculty do not).
app.get('/api/equipment', auth, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const everything = req.user.role === 'admin';
  const staff = req.user.role === 'admin' || req.user.role === 'lab';
  const rows = db.prepare(`select e.*, d.name department from equipment e
      left join departments d on d.id=e.department_id ${everything ? '' : 'where e.department_id=?'} order by e.name`)
    .all(...(everything ? [] : [req.user.department_id]))
    .map(e => ({ ...e, available_today: available(e.id, today, today), damaged: damagedUnits(e.id),
      damaged_records: staff ? damagedList(e.id) : [] }));
  res.json(rows);
});

// Admin and lab personnel manage equipment. Lab personnel can only touch their own department.
function ownsEquipment(req, res, id) {
  const e = db.prepare('select department_id from equipment where id=?').get(id);
  if (!e) { res.status(404).json({ error: 'Equipment not found.' }); return false; }
  if (req.user.role === 'lab' && e.department_id !== req.user.department_id) {
    res.status(403).json({ error: 'This equipment belongs to another department.' }); return false;
  }
  return true;
}
app.post('/api/equipment', auth, only('admin', 'lab'), (req, res) => {
  const { name, category, qty } = req.body;
  const dept = req.user.role === 'lab' ? req.user.department_id : req.body.departmentId;
  if (!name || !String(name).trim() || !(qty >= 0)) return res.status(400).json({ error: 'Name and quantity are required.' });
  if (!deptExists(dept)) return res.status(400).json({ error: 'Choose a department. Add one in the Departments tab first.' });
  const r = db.prepare('insert into equipment(name,category,qty,department_id) values(?,?,?,?)')
    .run(String(name).trim(), category || 'General', qty, Number(dept));
  log(`EQUIPMENT ADDED   ${name} x${qty}  by ${req.user.name} (${req.user.role})`);
  res.json({ id: r.lastInsertRowid });
});
app.patch('/api/equipment/:id', auth, only('admin', 'lab'), (req, res) => {
  if (!ownsEquipment(req, res, req.params.id)) return;
  if (!(req.body.qty >= 0)) return res.status(400).json({ error: 'Quantity must be 0 or more.' });
  db.prepare('update equipment set qty=? where id=?').run(req.body.qty, req.params.id);
  log(`EQUIPMENT QTY   #${req.params.id} set to ${req.body.qty}  by ${req.user.name} (${req.user.role})`);
  res.json({ ok: true });
});
app.delete('/api/equipment/:id', auth, only('admin', 'lab'), (req, res) => {
  if (!ownsEquipment(req, res, req.params.id)) return;
  db.prepare('delete from equipment where id=?').run(req.params.id);
  log(`EQUIPMENT REMOVED   #${req.params.id}  by ${req.user.name} (${req.user.role})`);
  res.json({ ok: true });
});

// ---------- Requests ----------
// Every request comes with the equipment's department, plus the requester's name,
// role, ID number and enrolled department (used by the Borrow history tab).
const SELECT = `select r.*, e.name equipment, e.department_id department_id, d.name department,
  u.name requester, u.role requester_role, u.id_number requester_id, ud.name requester_department
  from requests r join equipment e on e.id=r.equipment_id
  left join departments d on d.id=e.department_id
  join users u on u.id=r.user_id
  left join departments ud on ud.id=u.department_id`;

// Students and faculty request. The lab reviews and forwards it, then the admin decides.
// They can only request equipment of their own enrolled department.
app.post('/api/requests', auth, only('student', 'faculty'), (req, res) => {
  const { equipmentId, qty, type, from, to, purpose } = req.body;
  const today = new Date().toISOString().slice(0, 10);
  // Borrowed items past their return date must be returned (with their condition) before a new request.
  const late = db.prepare(`select count(*) n from requests where user_id=? and type='borrow'
    and status='Approved' and return_condition is null and date_to<?`).get(req.user.id, today).n;
  if (late) return res.status(403).json({ error: 'You still have borrowed items that must be returned. Open My requests, tap Return item and choose the condition.' });
  if (!['borrow', 'reserve'].includes(type)) return res.status(400).json({ error: 'Choose borrow or reserve.' });
  if (!isDate(from) || !isDate(to) || to < from || from < today) return res.status(400).json({ error: 'Check your dates.' });
  if (!(qty >= 1) || !purpose || !purpose.trim()) return res.status(400).json({ error: 'Quantity and purpose are required.' });
  const eq = db.prepare('select name, department_id from equipment where id=?').get(equipmentId);
  if (!eq) return res.status(404).json({ error: 'Equipment not found.' });
  if (eq.department_id !== req.user.department_id)
    return res.status(403).json({ error: 'You can only borrow or reserve equipment from your own department.' });
  const free = available(equipmentId, from, to);
  if (free < qty) return res.status(409).json({ error: `Only ${Math.max(free, 0)} available for those dates.` });
  const r = db.prepare(`insert into requests(equipment_id,user_id,qty,type,date_from,date_to,purpose) values(?,?,?,?,?,?,?)`)
    .run(equipmentId, req.user.id, qty, type, type === 'borrow' ? today : from, to, purpose.trim());
  log(`NEW REQUEST #${r.lastInsertRowid}   ${req.user.name} (${req.user.role}) asks for ${qty} x ${eq.name}  ${type}  ${type === 'borrow' ? today : from} to ${to}`);
  res.json({ id: r.lastInsertRowid, status: 'Pending' });
});

app.get('/api/requests/mine', auth, (req, res) =>
  res.json(db.prepare(`${SELECT} where r.user_id=? order by r.id desc`).all(req.user.id)));

// Lab sees the requests of its own department. Admin sees only the ones the lab sent forward.
// For the admin, requests that need a decision (forwarded, or a return to confirm) come first.
app.get('/api/requests/review', auth, only('lab', 'admin'), (req, res) => {
  const adm = req.user.role === 'admin';
  const lab = req.user.role === 'lab';
  const hide = adm ? "and r.status not in ('Pending','Cancelled')" : '';
  const first = adm ? "(r.status='Forwarded' or (r.status='Approved' and r.return_condition='Good')) desc, " : '';
  res.json(db.prepare(`${SELECT} where u.role in ('student','faculty') ${hide} ${lab ? 'and e.department_id=?' : ''} order by ${first}r.id desc`)
    .all(...(lab ? [req.user.department_id] : [])));
});

// Every request. Admin sees all of them, lab personnel see their own department's.
// The Borrow history tab uses this list.
app.get('/api/requests', auth, only('admin', 'lab'), (req, res) => {
  const lab = req.user.role === 'lab';
  res.json(db.prepare(`${SELECT} ${lab ? 'where e.department_id=?' : ''} order by r.id desc`)
    .all(...(lab ? [req.user.department_id] : [])));
});

// Lab can only forward a pending request to the admin.
// Only the admin can approve or reject a forwarded request.
// Returns are recorded with the item's condition (see "Returns and penalties" below).
const MOVES = {
  lab:   [['Pending', 'Forwarded']],
  admin: [['Forwarded', 'Approved'], ['Forwarded', 'Rejected']]
};
app.patch('/api/requests/:id', auth, only('lab', 'admin'), (req, res) => {
  const status = req.body.status;
  const r = db.prepare(`${SELECT} where r.id=?`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Request not found.' });
  if (!REVIEWS[req.user.role].includes(r.requester_role)) return res.status(403).json({ error: 'You cannot review this request.' });
  if (req.user.role === 'lab' && r.department_id !== req.user.department_id)
    return res.status(403).json({ error: 'This request belongs to another department.' });
  const ok = MOVES[req.user.role].some(m => m[0] === r.status && m[1] === status) &&
             !(status === 'Returned' && r.type !== 'borrow');
  if (!ok) return res.status(400).json({ error: req.user.role === 'lab'
    ? 'Laboratory personnel can only send pending requests to the admin.'
    : `You cannot change a ${r.status} request to ${status}.` });
  if (status === 'Approved' && available(r.equipment_id, r.date_from, r.date_to) < r.qty)
    return res.status(409).json({ error: 'Not enough stock for those dates.' });
  const col = status === 'Forwarded' ? 'forwarded_by' : 'reviewed_by';
  db.prepare(`update requests set status=?, ${col}=? where id=?`).run(status, req.user.id, r.id);
  log(`REQUEST #${r.id} ${status === 'Forwarded' ? 'SENT TO ADMIN' : status.toUpperCase()}   ${r.requester}'s ${r.qty} x ${r.equipment}  by ${req.user.name} (${req.user.role})`);
  res.json({ ok: true, status });
});

app.post('/api/requests/:id/cancel', auth, (req, res) => {
  const r = db.prepare('update requests set status=\'Cancelled\' where id=? and user_id=? and status=\'Pending\'').run(req.params.id, req.user.id);
  if (r.changes) log(`REQUEST #${req.params.id} CANCELLED   by ${req.user.name}`);
  r.changes ? res.json({ ok: true }) : res.status(400).json({ error: 'Only your pending requests can be cancelled.' });
});

// ---------- Students and faculty (admin and lab) ----------
// Admin sees every student and faculty member. Lab personnel see only the people
// who requested equipment from their department, with counts for that department only.
// Each person comes with the department they are enrolled in.
app.get('/api/people', auth, only('admin', 'lab'), (req, res) => {
  if (req.user.role === 'lab')
    return res.json(db.prepare(`select u.id, u.name, u.id_number, u.role, u.department_id, d.name department,
        count(r.id) total,
        coalesce(sum(r.status='Approved' and r.type='borrow'),0) borrowing,
        coalesce(sum(r.status='Forwarded'),0) waiting
      from users u join requests r on r.user_id=u.id join equipment e on e.id=r.equipment_id
      left join departments d on d.id=u.department_id
      where u.role in ('student','faculty') and e.department_id=? group by u.id order by u.name`)
      .all(req.user.department_id));
  res.json(db.prepare(`select u.id, u.name, u.id_number, u.role, u.department_id, d.name department,
      count(r.id) total,
      coalesce(sum(r.status='Approved' and r.type='borrow'),0) borrowing,
      coalesce(sum(r.status='Forwarded'),0) waiting
    from users u left join requests r on r.user_id=u.id
    left join departments d on d.id=u.department_id
    where u.role in ('student','faculty') group by u.id order by u.name`).all());
});

app.get('/api/people/:id', auth, only('admin', 'lab'), (req, res) => {
  const lab = req.user.role === 'lab';
  const p = db.prepare(`select u.id, u.name, u.id_number, u.role, u.department_id, d.name department
    from users u left join departments d on d.id=u.department_id
    where u.id=? and u.role in ('student','faculty')`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Person not found.' });
  p.requests = db.prepare(`${SELECT} where r.user_id=? ${lab ? 'and e.department_id=?' : ''} order by r.id desc`)
    .all(...(lab ? [p.id, req.user.department_id] : [p.id]));
  if (lab && !p.requests.length) return res.status(404).json({ error: 'This person has no requests in your department.' });
  res.json(p);
});

// ---------- Returns and penalties ----------
// The borrower (for their own loan) or the lab records the item's condition when it comes back.
// A Good return waits for the admin to confirm it. Only then does the stock go back up.
// A Damaged return goes straight to the admin's Penalties tab. The damaged units are NOT added
// back to the available stock until the admin marks them repaired or replaced.
// Any good units of the same loan (qty minus damaged) do go back.
app.post('/api/requests/:id/return', auth, only('student', 'faculty', 'lab'), (req, res) => {
  const r = db.prepare(`${SELECT} where r.id=?`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Request not found.' });
  if (req.user.role !== 'lab' && r.user_id !== req.user.id) return res.status(403).json({ error: 'You can only return your own items.' });
  if (req.user.role === 'lab' && r.department_id !== req.user.department_id)
    return res.status(403).json({ error: 'This item belongs to another department.' });
  if (r.status !== 'Approved' || r.type !== 'borrow') return res.status(400).json({ error: 'This item is not out on loan.' });
  if (r.return_condition) return res.status(400).json({ error: 'The return was already sent. It is waiting for the admin to confirm.' });
  const cond = req.body.condition, notes = String(req.body.notes || '').trim();
  if (!['Good', 'Damaged'].includes(cond)) return res.status(400).json({ error: 'Choose the condition of the item.' });
  if (cond === 'Damaged' && notes.length < 5) return res.status(400).json({ error: 'Describe what is damaged.' });
  const now = new Date().toISOString();
  if (cond === 'Good') {
    db.prepare(`update requests set return_condition='Good', return_notes=?, returned_at=? where id=?`).run(notes, now, r.id);
    log(`RETURN SENT #${r.id}   ${r.requester}'s ${r.qty} x ${r.equipment}  condition: GOOD  recorded by ${req.user.name} (${req.user.role})  waiting for the admin to confirm`);
    return res.json({ ok: true, waiting: true });
  }
  // How many units are damaged. A single unit is always 1. Otherwise the person enters it.
  const dq = r.qty === 1 ? 1 : Number(req.body.damagedQty);
  if (!Number.isInteger(dq) || dq < 1 || dq > r.qty)
    return res.status(400).json({ error: 'Enter how many units are damaged (1 to ' + r.qty + ').' });
  db.prepare(`update requests set status='Returned', return_condition='Damaged', return_notes=?, returned_at=?, penalty_status='Pending', damaged_qty=?, repaired_qty=0 where id=?`)
    .run(notes, now, dq, r.id);
  log(`ITEM RETURNED #${r.id}   ${r.requester}'s ${r.qty} x ${r.equipment}  condition: DAMAGED (${dq} damaged, not added back to the available stock)  recorded by ${req.user.name} (${req.user.role})`);
  log(`DAMAGE REPORTED #${r.id}   waiting for the admin to decide on a penalty`);
  res.json({ ok: true, waiting: false });
});

// The admin confirms a returned item in good condition. The request becomes Returned,
// so it no longer counts as borrowed and the equipment's available number goes up by its quantity.
app.post('/api/requests/:id/confirm-return', auth, only('admin'), (req, res) => {
  const r = db.prepare(`${SELECT} where r.id=?`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Request not found.' });
  if (r.status !== 'Approved' || r.return_condition !== 'Good')
    return res.status(400).json({ error: 'There is no returned item waiting for confirmation.' });
  db.prepare(`update requests set status='Returned', return_confirmed_by=?, return_confirmed_at=? where id=?`)
    .run(req.user.id, new Date().toISOString(), r.id);
  const today = new Date().toISOString().slice(0, 10);
  log(`RETURN CONFIRMED #${r.id}   ${r.requester}'s ${r.qty} x ${r.equipment}  +${r.qty} available  by ${req.user.name}`);
  res.json({ ok: true, available: available(r.equipment_id, today, today) });
});

// The admin marks damaged units as repaired or replaced. Those units go back into the available
// stock for everyone (lab personnel, admin, students and faculty). "qty" is how many units;
// if it is left out, all the units that are still damaged are marked.
app.post('/api/requests/:id/repair', auth, only('admin'), (req, res) => {
  const r = db.prepare(`${SELECT} where r.id=?`).get(req.params.id);
  if (!r || r.return_condition !== 'Damaged') return res.status(404).json({ error: 'No damaged return found.' });
  const damaged = r.damaged_qty || r.qty, done = r.repaired_qty || 0, left = damaged - done;
  if (left < 1) return res.status(400).json({ error: 'All the damaged units of this return were already repaired or replaced.' });
  const raw = req.body.qty;
  const n = (raw === undefined || raw === null || raw === '') ? left : Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > left)
    return res.status(400).json({ error: 'Enter how many units were repaired or replaced (1 to ' + left + ').' });
  db.prepare('update requests set repaired_qty=?, repaired_at=?, repaired_by=? where id=?')
    .run(done + n, new Date().toISOString(), req.user.id, r.id);
  const today = new Date().toISOString().slice(0, 10);
  const now = available(r.equipment_id, today, today);
  log(`DAMAGED UNITS REPAIRED #${r.id}   ${n} x ${r.equipment} (from ${r.requester}'s return)  +${n} available  by ${req.user.name}`);
  res.json({ ok: true, available: now });
});

// Damaged returns. Admin sees all of them and decides on a penalty.
// Lab personnel see their own department's (view only).
app.get('/api/penalties', auth, only('admin', 'lab'), (req, res) => {
  const lab = req.user.role === 'lab';
  res.json(db.prepare(`${SELECT} where r.return_condition='Damaged' ${lab ? 'and e.department_id=?' : ''}
    order by (r.penalty_status='Pending') desc, r.id desc`).all(...(lab ? [req.user.department_id] : [])));
});

app.post('/api/requests/:id/penalty', auth, only('admin'), (req, res) => {
  const r = db.prepare(`${SELECT} where r.id=?`).get(req.params.id);
  if (!r || r.return_condition !== 'Damaged') return res.status(404).json({ error: 'No damaged return found.' });
  const { action } = req.body;
  if (action === 'set' || action === 'waive') {
    if (r.penalty_status !== 'Pending') return res.status(400).json({ error: 'A decision was already made for this one.' });
    if (action === 'waive') {
      db.prepare("update requests set penalty_status='Waived', penalized_by=? where id=?").run(req.user.id, r.id);
      log(`PENALTY WAIVED #${r.id}   ${r.requester}  by ${req.user.name}`);
    } else {
      const amount = Number(req.body.amount), note = String(req.body.note || '').trim();
      if (!(amount > 0)) return res.status(400).json({ error: 'Enter a penalty amount above 0.' });
      if (!note) return res.status(400).json({ error: 'Add a reason for the penalty.' });
      db.prepare("update requests set penalty_status='Unpaid', penalty_amount=?, penalty_note=?, penalized_by=? where id=?")
        .run(amount, note, req.user.id, r.id);
      log(`PENALTY SET #${r.id}   ${r.requester} owes PHP ${amount.toFixed(2)}  for ${r.equipment}  by ${req.user.name}`);
    }
  } else if (action === 'paid') {
    if (r.penalty_status !== 'Unpaid') return res.status(400).json({ error: 'There is no unpaid penalty.' });
    const receipt = String(req.body.receipt || '').trim().toUpperCase();
    if (receipt.length < 3) return res.status(400).json({ error: 'Enter the official receipt number.' });
    if (db.prepare('select 1 from requests where receipt_no=? and id<>?').get(receipt, r.id))
      return res.status(409).json({ error: 'That receipt number was already used for another penalty.' });
    db.prepare("update requests set penalty_status='Paid', receipt_no=?, paid_at=? where id=?")
      .run(receipt, new Date().toISOString(), r.id);
    log(`PENALTY PAID #${r.id}   ${r.requester}  PHP ${Number(r.penalty_amount).toFixed(2)}  receipt ${receipt}  confirmed by ${req.user.name}`);
  } else return res.status(400).json({ error: 'Unknown action.' });
  res.json({ ok: true });
});

// ---------- Edit or remove accounts (admin) ----------
app.patch('/api/users/:id', auth, only('admin'), (req, res) => {
  const u = db.prepare("select * from users where id=? and role in ('student','faculty','lab')").get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Enter the full name.' });
  const idNumber = cleanId(u.role, req.body.idNumber);
  if (!ID_RULES[u.role].re.test(idNumber)) return res.status(400).json({ error: ID_RULES[u.role].msg });
  const pw = String(req.body.password || '');
  if (pw && pw.length < 8) return res.status(400).json({ error: 'A new password needs 8+ characters.' });
  // Lab personnel, students and faculty all have a department.
  if (!deptExists(req.body.departmentId)) return res.status(400).json({ error: 'Choose a department.' });
  const dept = Number(req.body.departmentId);
  try {
    db.prepare('update users set name=?, id_number=?, department_id=? where id=?').run(name, idNumber, dept, u.id);
    if (pw) db.prepare('update users set hash=? where id=?').run(bcrypt.hashSync(pw, 10), u.id);
  } catch { return res.status(409).json({ error: 'That ID number is already registered.' }); }
  log(`ACCOUNT EDITED   ${u.role}  ${idNumber}  ${name}  (${deptName(dept)})${pw ? '  (password reset)' : ''}  by ${req.user.name}`);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, only('admin'), (req, res) => {
  const u = db.prepare("select * from users where id=? and role in ('student','faculty','lab')").get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  try { db.prepare('delete from users where id=?').run(u.id); }
  catch { return res.status(409).json({ error: 'This account has request history, so it cannot be removed. Edit it instead.' }); }
  log(`ACCOUNT REMOVED   ${u.role}  ${u.id_number}  ${u.name}  by ${req.user.name}`);
  res.json({ ok: true });
});

// ---------- Departments (admin) ----------
app.get('/api/departments', auth, only('admin'), (req, res) => {
  const deps = db.prepare('select * from departments order by name').all();
  const labs = db.prepare("select id, name, id_number, department_id from users where role='lab' order by name").all();
  const counts = db.prepare('select department_id, count(*) n from equipment group by department_id').all();
  res.json(deps.map(d => ({ ...d, labs: labs.filter(l => l.department_id === d.id),
    equipment: (counts.find(c => c.department_id === d.id) || { n: 0 }).n })));
});
app.post('/api/departments', auth, only('admin'), (req, res) => {
  const name = String(req.body.name || '').trim();
  if (name.length < 2) return res.status(400).json({ error: 'Enter the department name.' });
  // Capital letters do not make a new department.
  if (db.prepare('select 1 from departments where lower(name)=lower(?)').get(name))
    return res.status(409).json({ error: 'That department already exists.' });
  try {
    db.prepare('insert into departments(name) values(?)').run(name);
    log(`DEPARTMENT ADDED   ${name}  by ${req.user.name}`);
    res.json({ ok: true });
  } catch { res.status(409).json({ error: 'That department already exists.' }); }
});
app.delete('/api/departments/:id', auth, only('admin'), (req, res) => {
  const id = Number(req.params.id);
  // A department that still has equipment or any account (lab, student or faculty) cannot be removed.
  if (db.prepare('select 1 from equipment where department_id=?').get(id) ||
      db.prepare('select 1 from users where department_id=?').get(id))
    return res.status(409).json({ error: 'This department still has equipment or accounts.' });
  db.prepare('delete from departments where id=?').run(id);
  log(`DEPARTMENT REMOVED   #${id}  by ${req.user.name}`);
  res.json({ ok: true });
});

// The admin creates laboratory personnel inside a department.
app.post('/api/departments/:id/lab', auth, only('admin'), (req, res) => {
  const u = createUser(res, { ...req.body, role: 'lab', departmentId: req.params.id }, ['lab']);
  if (u && u.id) {
    log(`LAB PERSONNEL ADDED   ${cleanId('lab', req.body.idNumber)}  ${u.name}  by ${req.user.name}`);
    res.json({ id: u.id });
  }
});

// ---------- Stock: what is borrowed, reserved, damaged and left (lab and admin) ----------
app.get('/api/stock', auth, only('lab', 'admin'), (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const holders = db.prepare(`select r.id, r.equipment_id, r.qty, r.type, r.date_from, r.date_to, r.return_condition,
      u.name requester, u.id_number, u.role
    from requests r join users u on u.id=r.user_id
    where r.status='Approved' and (r.type='borrow' or r.date_to>=?) order by r.date_to`).all(today);
  const rows = db.prepare('select * from equipment order by name').all()
    .filter(e => req.user.role === 'admin' || e.department_id === req.user.department_id).map(e => {
    const h = holders.filter(x => x.equipment_id === e.id);
    const sum = t => h.filter(x => x.type === t).reduce((n, x) => n + x.qty, 0);
    return { ...e, borrowed: sum('borrow'), reserved: sum('reserve'), damaged: damagedUnits(e.id),
      available: available(e.id, today, today), holders: h };
  });
  res.json(rows);
});

// Show the real error instead of a blank "Something went wrong".
app.use((err, req, res, next) => {
  console.error('ERROR', err.message);
  res.status(500).json({ error: 'Server error: ' + err.message });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) app.listen(PORT, () => console.log('Running on http://localhost:' + PORT));
module.exports = app;