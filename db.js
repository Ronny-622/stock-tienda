const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'inventory.db');
const dbDir = path.dirname(dbPath);

fs.mkdirSync(dbDir, { recursive: true });

const db = new sqlite3.Database(dbPath);

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function passwordMatchesHash(password, encodedHash) {
  const [scheme, salt, storedHash] = String(encodedHash || '').split('$');
  if (scheme !== 'scrypt' || !salt || !storedHash) return false;
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(storedHash, 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) return reject(err);
      resolve({ id: this.lastID, changes: this.changes, ok: true });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function seedDefaultProducts() {
  const starterProducts = [
    { id: 'p1', brand: 'Apple', model: 'iPhone 15', storage: '128 GB', sku: 'APL-IP15-128', price: 799, stock: 8 },
    { id: 'p2', brand: 'Samsung', model: 'Galaxy A55', storage: '256 GB', sku: 'SAM-A55-256', price: 449, stock: 12 },
    { id: 'p3', brand: 'Xiaomi', model: 'Redmi Note 13 Pro', storage: '256 GB', sku: 'XIA-RN13P-256', price: 329, stock: 4 },
    { id: 'p4', brand: 'Motorola', model: 'Edge 50 Fusion', storage: '256 GB', sku: 'MOT-E50F-256', price: 399, stock: 7 },
    { id: 'p5', brand: 'Apple', model: 'iPhone 14', storage: '128 GB', sku: 'APL-IP14-128', price: 649, stock: 3 },
    { id: 'p6', brand: 'Samsung', model: 'Galaxy S24', storage: '256 GB', sku: 'SAM-S24-256', price: 899, stock: 0 },
    { id: 'p7', brand: 'Apple', model: 'iPhone 16', storage: '256 GB', sku: 'APL-IP16-256', price: 999, stock: 10 }
  ];

  return run(
    `INSERT OR IGNORE INTO products (id, brand, model, storage, sku, price, stock)
     VALUES (?, ?, ?, ?, ?, ?, ?),
            (?, ?, ?, ?, ?, ?, ?),
            (?, ?, ?, ?, ?, ?, ?),
            (?, ?, ?, ?, ?, ?, ?),
            (?, ?, ?, ?, ?, ?, ?),
            (?, ?, ?, ?, ?, ?, ?),
            (?, ?, ?, ?, ?, ?, ?);`,
    starterProducts.flatMap((item) => [item.id, item.brand, item.model, item.storage, item.sku, item.price, item.stock])
  );
}

async function initializeDatabase() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      passwordHash TEXT,
      isActive INTEGER NOT NULL DEFAULT 1,
      role TEXT NOT NULL CHECK(role IN ('admin','vendedor','contabilidad')),
      name TEXT NOT NULL
    );
  `);

  const userColumns = await all('PRAGMA table_info(users);');
  if (!userColumns.some((column) => column.name === 'passwordHash')) {
    await run('ALTER TABLE users ADD COLUMN passwordHash TEXT;');
  }
  if (!userColumns.some((column) => column.name === 'isActive')) {
    await run('ALTER TABLE users ADD COLUMN isActive INTEGER NOT NULL DEFAULT 1;');
  }

  await run(`
    CREATE TABLE IF NOT EXISTS sessions (
      tokenHash TEXT PRIMARY KEY,
      userId INTEGER NOT NULL,
      expiresAt TEXT NOT NULL,
      FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      brand TEXT NOT NULL,
      model TEXT NOT NULL,
      storage TEXT,
      sku TEXT UNIQUE NOT NULL,
      price REAL NOT NULL,
      stock INTEGER NOT NULL CHECK(stock >= 0)
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS sales (
      id TEXT PRIMARY KEY,
      invoiceNumber TEXT UNIQUE NOT NULL,
      date TEXT NOT NULL,
      brand TEXT NOT NULL,
      model TEXT NOT NULL,
      storage TEXT,
      customer TEXT NOT NULL,
      unitPrice REAL NOT NULL,
      total REAL NOT NULL,
      financing TEXT NOT NULL DEFAULT '{}',
      creditContract TEXT NOT NULL DEFAULT '{}',
      devices TEXT NOT NULL DEFAULT '[]'
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      saleId TEXT NOT NULL,
      amount REAL NOT NULL,
      principalAmount REAL NOT NULL,
      lateFeeAmount REAL NOT NULL,
      paymentDate TEXT NOT NULL,
      FOREIGN KEY(saleId) REFERENCES sales(id)
    );
  `);

  const existingUsers = await all('SELECT id, username, password, passwordHash FROM users;');
  const production = process.env.NODE_ENV === 'production';
  for (const user of existingUsers) {
    const hasDefaultPassword = user.password === '1234' || passwordMatchesHash('1234', user.passwordHash);
    if (production && hasDefaultPassword) {
      await run(
        'UPDATE users SET password = ?, passwordHash = ?, isActive = 0 WHERE id = ?;',
        ['[stored as hash]', `disabled$${crypto.randomBytes(32).toString('hex')}`, user.id]
      );
      continue;
    }
    if (user.passwordHash) continue;
    const passwordHash = hashPassword(user.password);
    await run(
      'UPDATE users SET password = ?, passwordHash = ?, isActive = ? WHERE id = ?;',
      ['[stored as hash]', passwordHash, isInsecureDemo ? 0 : 1, user.id]
    );
  }

  if (production) {
    const adminUsername = String(process.env.ADMIN_USERNAME || '').trim().toLowerCase();
    const adminPassword = process.env.ADMIN_PASSWORD || '';
    if (Boolean(adminUsername) !== Boolean(adminPassword)) {
      throw new Error('Configura juntos ADMIN_USERNAME y ADMIN_PASSWORD.');
    }
    if (adminUsername && adminPassword) {
      if (adminPassword.length < 12) {
        throw new Error('ADMIN_PASSWORD debe tener al menos 12 caracteres.');
      }
      const existingAdmin = await get('SELECT id, passwordHash, isActive FROM users WHERE username = ?', [adminUsername]);
      if (!existingAdmin) {
        await run(
          'INSERT INTO users (username, password, passwordHash, isActive, role, name) VALUES (?, ?, ?, 1, ?, ?);',
          [adminUsername, '[stored as hash]', hashPassword(adminPassword), 'admin', process.env.ADMIN_NAME || 'Administrador']
        );
      } else if (!existingAdmin.isActive || String(existingAdmin.passwordHash || '').startsWith('disabled$')) {
        await run(
          'UPDATE users SET password = ?, passwordHash = ?, isActive = 1, role = ?, name = ? WHERE id = ?;',
          ['[stored as hash]', hashPassword(adminPassword), 'admin', process.env.ADMIN_NAME || 'Administrador', existingAdmin.id]
        );
      }
    }

    const activeAdmins = await all("SELECT id FROM users WHERE role = 'admin' AND isActive = 1 AND passwordHash LIKE 'scrypt$%';");
    if (activeAdmins.length === 0) {
      throw new Error('No hay un administrador activo. Configura ADMIN_USERNAME y ADMIN_PASSWORD seguros antes de iniciar.');
    }

    const secondUsername = String(process.env.SECOND_USER_USERNAME || '').trim().toLowerCase();
    const secondPassword = process.env.SECOND_USER_PASSWORD || '';
    if (Boolean(secondUsername) !== Boolean(secondPassword)) {
      throw new Error('Configura juntos SECOND_USER_USERNAME y SECOND_USER_PASSWORD.');
    }
    if (secondUsername && secondPassword) {
      if (secondPassword.length < 12) {
        throw new Error('SECOND_USER_PASSWORD debe tener al menos 12 caracteres.');
      }
      if (secondUsername === adminUsername) {
        throw new Error('SECOND_USER_USERNAME debe ser distinto de ADMIN_USERNAME.');
      }
      const secondRole = process.env.SECOND_USER_ROLE || 'vendedor';
      if (!['vendedor', 'contabilidad'].includes(secondRole)) {
        throw new Error('SECOND_USER_ROLE debe ser vendedor o contabilidad.');
      }
      const existingSecondUser = await get('SELECT id, passwordHash, isActive FROM users WHERE username = ?', [secondUsername]);
      if (!existingSecondUser) {
        await run(
          'INSERT INTO users (username, password, passwordHash, isActive, role, name) VALUES (?, ?, ?, 1, ?, ?);',
          [secondUsername, '[stored as hash]', hashPassword(secondPassword), secondRole, process.env.SECOND_USER_NAME || secondUsername]
        );
      } else if (!existingSecondUser.isActive || String(existingSecondUser.passwordHash || '').startsWith('disabled$')) {
        await run(
          'UPDATE users SET password = ?, passwordHash = ?, isActive = 1, role = ?, name = ? WHERE id = ?;',
          ['[stored as hash]', hashPassword(secondPassword), secondRole, process.env.SECOND_USER_NAME || secondUsername, existingSecondUser.id]
        );
      }
    }
  } else {
    const userCount = await get('SELECT COUNT(*) AS total FROM users;');
    if (userCount.total === 0) {
      const defaultUsers = [
        { username: 'admin', password: '1234', role: 'admin', name: 'Administrador' },
        { username: 'vendedor', password: '1234', role: 'vendedor', name: 'Vendedor' },
        { username: 'contabilidad', password: '1234', role: 'contabilidad', name: 'Contabilidad' }
      ];

      for (const user of defaultUsers) {
        await run(
          'INSERT INTO users (username, password, passwordHash, isActive, role, name) VALUES (?, ?, ?, 1, ?, ?);',
          [user.username, '[stored as hash]', hashPassword(user.password), user.role, user.name]
        );
      }
    }
  }

  const existingProducts = await all('SELECT COUNT(*) AS total FROM products;');
  if (!production && (existingProducts[0]?.total ?? 0) === 0) {
    await seedDefaultProducts();
  }
}

module.exports = {
  db,
  run,
  get,
  all,
  initializeDatabase,
  seedDefaultProducts
};
