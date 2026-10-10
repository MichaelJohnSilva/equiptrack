const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rl = require('express-rate-limit');
const rateLimit = rl.rateLimit || rl;
const { db, initSchema, bootstrap } = require('./db');

const SECRET = process.env.JWT_SECRET || 'change-this-secret';

// The database is created and tidied before the first request is answered.
const ready = (async () => { await initSchema(); await bootstrap(); })();

// Who reviews whose requests.
const REVIEWS = { lab: ['student', 'faculty'], admin: ['student', 'faculty'] };
// Prints what happens to the terminal. Passwords are never logged.
const log = m => console.log('[' + new Date().toLocaleTimeString() + '] ' + m);
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '');
// Lets a route use await and still send its errors to the error handler at the bottom.
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const deptExists = async id => Number.isInteger(Number(id)) && !!(await db.get('select 1 as x from departments where id=?', Number(id)));
const deptName = async id => { const d = id ? await db.get('select name from departments where id=?', id) : null; return d ? d.name : null; };

// Units of an item that are damaged and NOT yet repaired or replaced. They are not available.
// For each damaged return: damaged units minus the units the admin marked as repaired or replaced.
async function damagedUnits(equipmentId) {
  return (await db.get(`select coalesce(sum(coalesce(damaged_qty, qty) - coalesce(repaired_qty, 0)),0) n from requests
    where equipment_id=? and return_condition='Damaged'`, equipmentId)).n;
}

// Every damaged return of an item (used by the Inventory cards of the admin and lab personnel).
function damagedList(equipmentId) {
  return db.all(`select r.id, r.qty, coalesce(r.damaged_qty, r.qty) damaged_qty,
      coalesce(r.repaired_qty, 0) repaired_qty, r.returned_at, r.return_notes, r.repaired_at,
      u.name requester, u.id_number
    from requests r join users u on u.id=r.user_id
    where r.equipment_id=? and r.return_condition='Damaged' order by r.id desc`, equipmentId);
}

// Available = total, minus what is out on approved loans for those dates, minus the damaged units
// that are still not repaired or replaced.
async function available(equipmentId, from, to) {
  const e = await db.get('select qty from equipment where id=?', equipmentId);
  if (!e) return null;
  const used = (await db.get(`select coalesce(sum(qty),0) n from requests
    where equipment_id=? and status='Approved' and date_from<=? and date_to>=?`, equipmentId, to, from)).n;
  return e.qty - used - await damagedUnits(equipmentId);
}

// Checks the sign-in token, and that the user still exists in the database.
const auth = async (req, res, next) => {
  try {
    const t = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    const u = await db.get('select id, name, role, department_id from users where id=?', t.id);
    if (!u) throw new Error('user no longer exists');
    req.user = { id: u.id, name: u.name, role: u.role, department_id: u.department_id };
  } catch { return res.status(401).json({ error: 'Please sign in.' }); }
  next();
};
const only = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Not allowed for your role.' });

const app = express();
// Render sits behind a proxy. Without this, every visitor looks like the same address
// and the sign-in limit below would block everyone at once.
app.set('trust proxy', 1);
app.use(express.json());
app.use(ah(async (req, res, next) => { await ready; next(); }));
app.use(express.static('public'));

// Render uses this to check that the server is running.
app.get('/health', (req, res) => res.send('ok'));

// Stops people from guessing passwords: 20 sign-in attempts per 15 minutes from one address.
const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  message: { error: 'Too many sign-in attempts. Try again in 15 minutes.' }
});

const token = u => jwt.sign({ id: u.id, name: u.name, role: u.role }, SECRET, { expiresIn: '8h' });

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
async function createUser(res, { name, idNumber, password, role, departmentId }, allowed) {
  if (!name || !String(name).trim() || !password || password.length < 8)
    return res.status(400).json({ error: 'Name and a password of 8+ characters are required.' });
  if (!allowed.includes(role) || !ID_RULES[role]) return res.status(400).json({ error: 'Choose a valid role.' });
  const id = cleanId(role, idNumber);
  if (!ID_RULES[role].re.test(id)) return res.status(400).json({ error: ID_RULES[role].msg });
  if (role !== 'admin' && !(await deptExists(departmentId)))
    return res.status(400).json({ error: role === 'lab'
      ? 'Choose the department of this laboratory personnel.'
      : 'Choose the department you are enrolled in.' });
  if (await db.get('select 1 as x from users where id_number=?', id))
    return res.status(409).json({ error: 'That ID number is already registered.' });
  try {
    const dept = Number(departmentId);
    const r = await db.run('insert into users(name,id_number,hash,role,department_id) values(?,?,?,?,?)',
      String(name).trim(), id, bcrypt.hashSync(password, 10), role, dept);
    return { id: r.lastInsertRowid, name: String(name).trim(), role, department: await deptName(dept) };
  } catch { return res.status(409).json({ error: 'That ID number is already registered.' }); }
}

// Students and faculty can sign up themselves. They choose their enrolled department.
app.post('/api/register', ah(async (req, res) => {
  const u = await createUser(res, req.body, ['student', 'faculty']);
  if (u && u.id) {
    log(`NEW ACCOUNT   ${u.role}  ${cleanId(u.role, req.body.idNumber)}  ${u.name}  (${u.department})`);
    res.json({ token: token(u), name: u.name, role: u.role, department: u.department });
  }
}));

// The admin can create student and faculty accounts. Lab personnel are added inside a department.
app.post('/api/users', auth, only('admin'), ah(async (req, res) => {
  const u = await createUser(res, req.body, ['student', 'faculty']);
  if (u && u.id) {
    log(`ACCOUNT MADE BY ADMIN   ${u.role}  ${cleanId(u.role, req.body.idNumber)}  ${u.name}  (${u.department})`);
    res.json({ id: u.id });
  }
}));

// The sign-in page needs the department names before anyone is signed in (names only, nothing private).
app.get('/api/public/departments', ah(async (req, res) =>
  res.json(await db.all('select id, name from departments order by name'))));

// Sign in. The page says which kind of account it is signing in as ("as"),
// and laboratory personnel must also choose their assigned department.
app.post('/api/login', loginLimit, ah(async (req, res) => {
  const raw = String(req.body.idNumber || '').trim().toUpperCase();
  const u = await db.get('select * from users where id_number in (?,?)', raw.replace(/\s/g, ''), raw.replace(/[\s-]/g, ''));
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
  res.json({ token: token(u), name: u.name, role: u.role, department: await deptName(u.department_id) });
}));

// Who is signed in, with their department. The page uses this for the header.
app.get('/api/me', auth, ah(async (req, res) =>
  res.json({ name: req.user.name, role: req.user.role,
    department: await deptName(req.user.department_id), department_id: req.user.department_id })));

// ---------- Equipment ----------
// Admin sees everything. Everyone else (lab personnel, students, faculty) sees only the
// equipment of their own department. A student with no department sees nothing.
// "damaged" is the number of units that are damaged and not yet repaired or replaced.
// Admin and lab personnel also get the list of damaged returns (students and faculty do not).
app.get('/api/equipment', auth, ah(async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const everything = req.user.role === 'admin';
  const staff = req.user.role === 'admin' || req.user.role === 'lab';
  const rows = await db.all(`select e.*, d.name department from equipment e
      left join departments d on d.id=e.department_id ${everything ? '' : 'where e.department_id=?'} order by e.name`,
    ...(everything ? [] : [req.user.department_id]));
  for (const e of rows) {
    e.available_today = await available(e.id, today, today);
    e.damaged = await damagedUnits(e.id);
    e.damaged_records = staff ? await damagedList(e.id) : [];
  }
  res.json(rows);
}));

// Admin and lab personnel manage equipment. Lab personnel can only touch their own department.
async function ownsEquipment(req, res, id) {
  const e = await db.get('select department_id from equipment where id=?', id);
  if (!e) { res.status(404).json({ error: 'Equipment not found.' }); return false; }
  if (req.user.role === 'lab' && e.department_id !== req.user.department_id) {
    res.status(403).json({ error: 'This equipment belongs to another department.' }); return false;
  }
  return true;
}
app.post('/api/equipment', auth, only('admin', 'lab'), ah(async (req, res) => {
  const { name, category, qty } = req.body;
  const dept = req.user.role === 'lab' ? req.user.department_id : req.body.departmentId;
  if (!name || !String(name).trim() || !(qty >= 0)) return res.status(400).json({ error: 'Name and quantity are required.' });
  if (!(await deptExists(dept))) return res.status(400).json({ error: 'Choose a department. Add one in the Departments tab first.' });
  const r = await db.run('insert into equipment(name,category,qty,department_id) values(?,?,?,?)',
    String(name).trim(), category || 'General', qty, Number(dept));
  log(`EQUIPMENT ADDED   ${name} x${qty}  by ${req.user.name} (${req.user.role})`);
  res.json({ id: r.lastInsertRowid });
}));
app.patch('/api/equipment/:id', auth, only('admin', 'lab'), ah(async (req, res) => {
  if (!(await ownsEquipment(req, res, req.params.id))) return;
  if (!(req.body.qty >= 0)) return res.status(400).json({ error: 'Quantity must be 0 or more.' });
  await db.run('update equipment set qty=? where id=?', req.body.qty, req.params.id);
  log(`EQUIPMENT QTY   #${req.params.id} set to ${req.body.qty}  by ${req.user.name} (${req.user.role})`);
  res.json({ ok: true });
}));
app.delete('/api/equipment/:id', auth, only('admin', 'lab'), ah(async (req, res) => {
  if (!(await ownsEquipment(req, res, req.params.id))) return;
  // The request history of the item goes with it.
  await db.run('delete from requests where equipment_id=?', req.params.id);
  await db.run('delete from equipment where id=?', req.params.id);
  log(`EQUIPMENT REMOVED   #${req.params.id}  by ${req.user.name} (${req.user.role})`);
  res.json({ ok: true });
}));

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
app.post('/api/requests', auth, only('student', 'faculty'), ah(async (req, res) => {
  const { equipmentId, qty, type, from, to, purpose } = req.body;
  const today = new Date().toISOString().slice(0, 10);
  // Borrowed items past their return date must be returned (with their condition) before a new request.
  const late = (await db.get(`select count(*) n from requests where user_id=? and type='borrow'
    and status='Approved' and return_condition is null and date_to<?`, req.user.id, today)).n;
  if (late) return res.status(403).json({ error: 'You still have borrowed items that must be returned. Open My requests, tap Return item and choose the condition.' });
  if (!['borrow', 'reserve'].includes(type)) return res.status(400).json({ error: 'Choose borrow or reserve.' });
  if (!isDate(from) || !isDate(to) || to < from || from < today) return res.status(400).json({ error: 'Check your dates.' });
  if (!(qty >= 1) || !purpose || !purpose.trim()) return res.status(400).json({ error: 'Quantity and purpose are required.' });
  const eq = await db.get('select name, department_id from equipment where id=?', equipmentId);
  if (!eq) return res.status(404).json({ error: 'Equipment not found.' });
  if (eq.department_id !== req.user.department_id)
    return res.status(403).json({ error: 'You can only borrow or reserve equipment from your own department.' });
  const free = await available(equipmentId, from, to);
  if (free < qty) return res.status(409).json({ error: `Only ${Math.max(free, 0)} available for those dates.` });
  const r = await db.run(`insert into requests(equipment_id,user_id,qty,type,date_from,date_to,purpose) values(?,?,?,?,?,?,?)`,
    equipmentId, req.user.id, qty, type, type === 'borrow' ? today : from, to, purpose.trim());
  log(`NEW REQUEST #${r.lastInsertRowid}   ${req.user.name} (${req.user.role}) asks for ${qty} x ${eq.name}  ${type}  ${type === 'borrow' ? today : from} to ${to}`);
  res.json({ id: r.lastInsertRowid, status: 'Pending' });
}));

app.get('/api/requests/mine', auth, ah(async (req, res) =>
  res.json(await db.all(`${SELECT} where r.user_id=? order by r.id desc`, req.user.id))));

// Lab sees the requests of its own department. Admin sees only the ones the lab sent forward.
// For the admin, requests that need a decision (forwarded, or a return to confirm) come first.
app.get('/api/requests/review', auth, only('lab', 'admin'), ah(async (req, res) => {
  const adm = req.user.role === 'admin';
  const lab = req.user.role === 'lab';
  const hide = adm ? "and r.status not in ('Pending','Cancelled')" : '';
  const first = adm ? "(r.status='Forwarded' or (r.status='Approved' and r.return_condition='Good')) desc, " : '';
  res.json(await db.all(`${SELECT} where u.role in ('student','faculty') ${hide} ${lab ? 'and e.department_id=?' : ''} order by ${first}r.id desc`,
    ...(lab ? [req.user.department_id] : [])));
}));

// Every request. Admin sees all of them, lab personnel see their own department's.
// The Borrow history tab uses this list.
app.get('/api/requests', auth, only('admin', 'lab'), ah(async (req, res) => {
  const lab = req.user.role === 'lab';
  res.json(await db.all(`${SELECT} ${lab ? 'where e.department_id=?' : ''} order by r.id desc`,
    ...(lab ? [req.user.department_id] : [])));
}));

// Lab can only forward a pending request to the admin.
// Only the admin can approve or reject a forwarded request.
// Returns are recorded with the item's condition (see "Returns and penalties" below).
const MOVES = {
  lab:   [['Pending', 'Forwarded']],
  admin: [['Forwarded', 'Approved'], ['Forwarded', 'Rejected']]
};
app.patch('/api/requests/:id', auth, only('lab', 'admin'), ah(async (req, res) => {
  const status = req.body.status;
  const r = await db.get(`${SELECT} where r.id=?`, req.params.id);
  if (!r) return res.status(404).json({ error: 'Request not found.' });
  if (!REVIEWS[req.user.role].includes(r.requester_role)) return res.status(403).json({ error: 'You cannot review this request.' });
  if (req.user.role === 'lab' && r.department_id !== req.user.department_id)
    return res.status(403).json({ error: 'This request belongs to another department.' });
  const ok = MOVES[req.user.role].some(m => m[0] === r.status && m[1] === status) &&
             !(status === 'Returned' && r.type !== 'borrow');
  if (!ok) return res.status(400).json({ error: req.user.role === 'lab'
    ? 'Laboratory personnel can only send pending requests to the admin.'
    : `You cannot change a ${r.status} request to ${status}.` });
  if (status === 'Approved' && (await available(r.equipment_id, r.date_from, r.date_to)) < r.qty)
    return res.status(409).json({ error: 'Not enough stock for those dates.' });
  const col = status === 'Forwarded' ? 'forwarded_by' : 'reviewed_by';
  await db.run(`update requests set status=?, ${col}=? where id=?`, status, req.user.id, r.id);
  log(`REQUEST #${r.id} ${status === 'Forwarded' ? 'SENT TO ADMIN' : status.toUpperCase()}   ${r.requester}'s ${r.qty} x ${r.equipment}  by ${req.user.name} (${req.user.role})`);
  res.json({ ok: true, status });
}));

app.post('/api/requests/:id/cancel', auth, ah(async (req, res) => {
  const r = await db.run("update requests set status='Cancelled' where id=? and user_id=? and status='Pending'", req.params.id, req.user.id);
  if (r.changes) log(`REQUEST #${req.params.id} CANCELLED   by ${req.user.name}`);
  r.changes ? res.json({ ok: true }) : res.status(400).json({ error: 'Only your pending requests can be cancelled.' });
}));

// ---------- Students and faculty (admin and lab) ----------
// Admin sees every student and faculty member. Lab personnel see only the people
// who requested equipment from their department, with counts for that department only.
// Each person comes with the department they are enrolled in.
app.get('/api/people', auth, only('admin', 'lab'), ah(async (req, res) => {
  if (req.user.role === 'lab')
    return res.json(await db.all(`select u.id, u.name, u.id_number, u.role, u.department_id, d.name department,
        count(r.id) total,
        coalesce(sum(r.status='Approved' and r.type='borrow'),0) borrowing,
        coalesce(sum(r.status='Forwarded'),0) waiting
      from users u join requests r on r.user_id=u.id join equipment e on e.id=r.equipment_id
      left join departments d on d.id=u.department_id
      where u.role in ('student','faculty') and e.department_id=? group by u.id order by u.name`,
      req.user.department_id));
  res.json(await db.all(`select u.id, u.name, u.id_number, u.role, u.department_id, d.name department,
      count(r.id) total,
      coalesce(sum(r.status='Approved' and r.type='borrow'),0) borrowing,
      coalesce(sum(r.status='Forwarded'),0) waiting
    from users u left join requests r on r.user_id=u.id
    left join departments d on d.id=u.department_id
    where u.role in ('student','faculty') group by u.id order by u.name`));
}));

app.get('/api/people/:id', auth, only('admin', 'lab'), ah(async (req, res) => {
  const lab = req.user.role === 'lab';
  const p = await db.get(`select u.id, u.name, u.id_number, u.role, u.department_id, d.name department
    from users u left join departments d on d.id=u.department_id
    where u.id=? and u.role in ('student','faculty')`, req.params.id);
  if (!p) return res.status(404).json({ error: 'Person not found.' });
  p.requests = await db.all(`${SELECT} where r.user_id=? ${lab ? 'and e.department_id=?' : ''} order by r.id desc`,
    ...(lab ? [p.id, req.user.department_id] : [p.id]));
  if (lab && !p.requests.length) return res.status(404).json({ error: 'This person has no requests in your department.' });
  res.json(p);
}));

// ---------- Returns and penalties ----------
// The borrower (for their own loan) or the lab records the item's condition when it comes back.
// A Good return waits for the admin to confirm it. Only then does the stock go back up.
// A Damaged return goes straight to the admin's Penalties tab. The damaged units are NOT added
// back to the available stock until the admin marks them repaired or replaced.
// Any good units of the same loan (qty minus damaged) do go back.
app.post('/api/requests/:id/return', auth, only('student', 'faculty', 'lab'), ah(async (req, res) => {
  const r = await db.get(`${SELECT} where r.id=?`, req.params.id);
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
    await db.run(`update requests set return_condition='Good', return_notes=?, returned_at=? where id=?`, notes, now, r.id);
    log(`RETURN SENT #${r.id}   ${r.requester}'s ${r.qty} x ${r.equipment}  condition: GOOD  recorded by ${req.user.name} (${req.user.role})  waiting for the admin to confirm`);
    return res.json({ ok: true, waiting: true });
  }
  // How many units are damaged. A single unit is always 1. Otherwise the person enters it.
  const dq = r.qty === 1 ? 1 : Number(req.body.damagedQty);
  if (!Number.isInteger(dq) || dq < 1 || dq > r.qty)
    return res.status(400).json({ error: 'Enter how many units are damaged (1 to ' + r.qty + ').' });
  await db.run(`update requests set status='Returned', return_condition='Damaged', return_notes=?, returned_at=?, penalty_status='Pending', damaged_qty=?, repaired_qty=0 where id=?`,
    notes, now, dq, r.id);
  log(`ITEM RETURNED #${r.id}   ${r.requester}'s ${r.qty} x ${r.equipment}  condition: DAMAGED (${dq} damaged, not added back to the available stock)  recorded by ${req.user.name} (${req.user.role})`);
  log(`DAMAGE REPORTED #${r.id}   waiting for the admin to decide on a penalty`);
  res.json({ ok: true, waiting: false });
}));

// The admin confirms a returned item in good condition. The request becomes Returned,
// so it no longer counts as borrowed and the equipment's available number goes up by its quantity.
app.post('/api/requests/:id/confirm-return', auth, only('admin'), ah(async (req, res) => {
  const r = await db.get(`${SELECT} where r.id=?`, req.params.id);
  if (!r) return res.status(404).json({ error: 'Request not found.' });
  if (r.status !== 'Approved' || r.return_condition !== 'Good')
    return res.status(400).json({ error: 'There is no returned item waiting for confirmation.' });
  await db.run(`update requests set status='Returned', return_confirmed_by=?, return_confirmed_at=? where id=?`,
    req.user.id, new Date().toISOString(), r.id);
  const today = new Date().toISOString().slice(0, 10);
  log(`RETURN CONFIRMED #${r.id}   ${r.requester}'s ${r.qty} x ${r.equipment}  +${r.qty} available  by ${req.user.name}`);
  res.json({ ok: true, available: await available(r.equipment_id, today, today) });
}));

// The admin marks damaged units as repaired or replaced. Those units go back into the available
// stock for everyone (lab personnel, admin, students and faculty). "qty" is how many units;
// if it is left out, all the units that are still damaged are marked.
app.post('/api/requests/:id/repair', auth, only('admin'), ah(async (req, res) => {
  const r = await db.get(`${SELECT} where r.id=?`, req.params.id);
  if (!r || r.return_condition !== 'Damaged') return res.status(404).json({ error: 'No damaged return found.' });
  const damaged = r.damaged_qty || r.qty, done = r.repaired_qty || 0, left = damaged - done;
  if (left < 1) return res.status(400).json({ error: 'All the damaged units of this return were already repaired or replaced.' });
  const raw = req.body.qty;
  const n = (raw === undefined || raw === null || raw === '') ? left : Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > left)
    return res.status(400).json({ error: 'Enter how many units were repaired or replaced (1 to ' + left + ').' });
  await db.run('update requests set repaired_qty=?, repaired_at=?, repaired_by=? where id=?',
    done + n, new Date().toISOString(), req.user.id, r.id);
  const today = new Date().toISOString().slice(0, 10);
  const now = await available(r.equipment_id, today, today);
  log(`DAMAGED UNITS REPAIRED #${r.id}   ${n} x ${r.equipment} (from ${r.requester}'s return)  +${n} available  by ${req.user.name}`);
  res.json({ ok: true, available: now });
}));

// Damaged returns. Admin sees all of them and decides on a penalty.
// Lab personnel see their own department's (view only).
app.get('/api/penalties', auth, only('admin', 'lab'), ah(async (req, res) => {
  const lab = req.user.role === 'lab';
  res.json(await db.all(`${SELECT} where r.return_condition='Damaged' ${lab ? 'and e.department_id=?' : ''}
    order by (r.penalty_status='Pending') desc, r.id desc`, ...(lab ? [req.user.department_id] : [])));
}));

app.post('/api/requests/:id/penalty', auth, only('admin'), ah(async (req, res) => {
  const r = await db.get(`${SELECT} where r.id=?`, req.params.id);
  if (!r || r.return_condition !== 'Damaged') return res.status(404).json({ error: 'No damaged return found.' });
  const { action } = req.body;
  if (action === 'set' || action === 'waive') {
    if (r.penalty_status !== 'Pending') return res.status(400).json({ error: 'A decision was already made for this one.' });
    if (action === 'waive') {
      await db.run("update requests set penalty_status='Waived', penalized_by=? where id=?", req.user.id, r.id);
      log(`PENALTY WAIVED #${r.id}   ${r.requester}  by ${req.user.name}`);
    } else {
      const amount = Number(req.body.amount), note = String(req.body.note || '').trim();
      if (!(amount > 0)) return res.status(400).json({ error: 'Enter a penalty amount above 0.' });
      if (!note) return res.status(400).json({ error: 'Add a reason for the penalty.' });
      await db.run("update requests set penalty_status='Unpaid', penalty_amount=?, penalty_note=?, penalized_by=? where id=?",
        amount, note, req.user.id, r.id);
      log(`PENALTY SET #${r.id}   ${r.requester} owes PHP ${amount.toFixed(2)}  for ${r.equipment}  by ${req.user.name}`);
    }
  } else if (action === 'paid') {
    if (r.penalty_status !== 'Unpaid') return res.status(400).json({ error: 'There is no unpaid penalty.' });
    const receipt = String(req.body.receipt || '').trim().toUpperCase();
    if (receipt.length < 3) return res.status(400).json({ error: 'Enter the official receipt number.' });
    if (await db.get('select 1 as x from requests where receipt_no=? and id<>?', receipt, r.id))
      return res.status(409).json({ error: 'That receipt number was already used for another penalty.' });
    await db.run("update requests set penalty_status='Paid', receipt_no=?, paid_at=? where id=?",
      receipt, new Date().toISOString(), r.id);
    log(`PENALTY PAID #${r.id}   ${r.requester}  PHP ${Number(r.penalty_amount).toFixed(2)}  receipt ${receipt}  confirmed by ${req.user.name}`);
  } else return res.status(400).json({ error: 'Unknown action.' });
  res.json({ ok: true });
}));

// ---------- Edit or remove accounts (admin) ----------
app.patch('/api/users/:id', auth, only('admin'), ah(async (req, res) => {
  const u = await db.get("select * from users where id=? and role in ('student','faculty','lab')", req.params.id);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Enter the full name.' });
  const idNumber = cleanId(u.role, req.body.idNumber);
  if (!ID_RULES[u.role].re.test(idNumber)) return res.status(400).json({ error: ID_RULES[u.role].msg });
  const pw = String(req.body.password || '');
  if (pw && pw.length < 8) return res.status(400).json({ error: 'A new password needs 8+ characters.' });
  // Lab personnel, students and faculty all have a department.
  if (!(await deptExists(req.body.departmentId))) return res.status(400).json({ error: 'Choose a department.' });
  const dept = Number(req.body.departmentId);
  if (await db.get('select 1 as x from users where id_number=? and id<>?', idNumber, u.id))
    return res.status(409).json({ error: 'That ID number is already registered.' });
  try {
    await db.run('update users set name=?, id_number=?, department_id=? where id=?', name, idNumber, dept, u.id);
    if (pw) await db.run('update users set hash=? where id=?', bcrypt.hashSync(pw, 10), u.id);
  } catch { return res.status(409).json({ error: 'That ID number is already registered.' }); }
  log(`ACCOUNT EDITED   ${u.role}  ${idNumber}  ${name}  (${await deptName(dept)})${pw ? '  (password reset)' : ''}  by ${req.user.name}`);
  res.json({ ok: true });
}));

app.delete('/api/users/:id', auth, only('admin'), ah(async (req, res) => {
  const u = await db.get("select * from users where id=? and role in ('student','faculty','lab')", req.params.id);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  if (await db.get('select 1 as x from requests where user_id=? or forwarded_by=? or reviewed_by=?', u.id, u.id, u.id))
    return res.status(409).json({ error: 'This account has request history, so it cannot be removed. Edit it instead.' });
  await db.run('delete from users where id=?', u.id);
  log(`ACCOUNT REMOVED   ${u.role}  ${u.id_number}  ${u.name}  by ${req.user.name}`);
  res.json({ ok: true });
}));

// ---------- Departments (admin) ----------
app.get('/api/departments', auth, only('admin'), ah(async (req, res) => {
  const deps = await db.all('select * from departments order by name');
  const labs = await db.all("select id, name, id_number, department_id from users where role='lab' order by name");
  const counts = await db.all('select department_id, count(*) n from equipment group by department_id');
  res.json(deps.map(d => ({ ...d, labs: labs.filter(l => l.department_id === d.id),
    equipment: (counts.find(c => c.department_id === d.id) || { n: 0 }).n })));
}));
app.post('/api/departments', auth, only('admin'), ah(async (req, res) => {
  const name = String(req.body.name || '').trim();
  if (name.length < 2) return res.status(400).json({ error: 'Enter the department name.' });
  // Capital letters do not make a new department.
  if (await db.get('select 1 as x from departments where lower(name)=lower(?)', name))
    return res.status(409).json({ error: 'That department already exists.' });
  try {
    await db.run('insert into departments(name) values(?)', name);
    log(`DEPARTMENT ADDED   ${name}  by ${req.user.name}`);
    res.json({ ok: true });
  } catch { res.status(409).json({ error: 'That department already exists.' }); }
}));
app.delete('/api/departments/:id', auth, only('admin'), ah(async (req, res) => {
  const id = Number(req.params.id);
  // A department that still has equipment or any account (lab, student or faculty) cannot be removed.
  if (await db.get('select 1 as x from equipment where department_id=?', id) ||
      await db.get('select 1 as x from users where department_id=?', id))
    return res.status(409).json({ error: 'This department still has equipment or accounts.' });
  await db.run('delete from departments where id=?', id);
  log(`DEPARTMENT REMOVED   #${id}  by ${req.user.name}`);
  res.json({ ok: true });
}));

// The admin creates laboratory personnel inside a department.
app.post('/api/departments/:id/lab', auth, only('admin'), ah(async (req, res) => {
  const u = await createUser(res, { ...req.body, role: 'lab', departmentId: req.params.id }, ['lab']);
  if (u && u.id) {
    log(`LAB PERSONNEL ADDED   ${cleanId('lab', req.body.idNumber)}  ${u.name}  by ${req.user.name}`);
    res.json({ id: u.id });
  }
}));

// ---------- Stock: what is borrowed, reserved, damaged and left (lab and admin) ----------
app.get('/api/stock', auth, only('lab', 'admin'), ah(async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const holders = await db.all(`select r.id, r.equipment_id, r.qty, r.type, r.date_from, r.date_to, r.return_condition,
      u.name requester, u.id_number, u.role
    from requests r join users u on u.id=r.user_id
    where r.status='Approved' and (r.type='borrow' or r.date_to>=?) order by r.date_to`, today);
  const items = (await db.all('select * from equipment order by name'))
    .filter(e => req.user.role === 'admin' || e.department_id === req.user.department_id);
  const rows = [];
  for (const e of items) {
    const h = holders.filter(x => x.equipment_id === e.id);
    const sum = t => h.filter(x => x.type === t).reduce((n, x) => n + x.qty, 0);
    rows.push({ ...e, borrowed: sum('borrow'), reserved: sum('reserve'), damaged: await damagedUnits(e.id),
      available: await available(e.id, today, today), holders: h });
  }
  res.json(rows);
}));

// Show the real error instead of a blank "Something went wrong".
app.use((err, req, res, next) => {
  console.error('ERROR', err.message);
  res.status(500).json({ error: 'Server error: ' + err.message });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  ready
    .then(() => app.listen(PORT, () => console.log('Running on http://localhost:' + PORT + '  (database: ' + (process.env.TURSO_DATABASE_URL ? 'Turso' : 'local file') + ')')))
    .catch(e => { console.error('Could not open the database: ' + e.message); process.exit(1); });
}
module.exports = app;
