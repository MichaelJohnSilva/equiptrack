// Run with: npm run data
const Database = require('better-sqlite3');
const db = new Database(process.env.DB_FILE || 'borrow.db', { readonly: true, fileMustExist: true });
console.log('\nUSERS (passwords are never shown)');
console.table(db.prepare('select id, name, id_number, role from users').all());
console.log('EQUIPMENT');
console.table(db.prepare('select id, name, category, qty from equipment').all());
console.log('REQUESTS');
console.table(db.prepare(`select r.id, u.name requester, u.role, e.name equipment, r.qty, r.type, r.date_from, r.date_to, r.status
  from requests r join users u on u.id=r.user_id join equipment e on e.id=r.equipment_id order by r.id desc`).all());