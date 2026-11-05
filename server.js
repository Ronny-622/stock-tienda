const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { initializeDatabase, all, get, run, seedDefaultProducts } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
const scrypt = promisify(crypto.scrypt);
const loginAttempts = new Map();

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return scrypt(password, salt, 64).then((hash) => `scrypt$${salt}$${hash.toString('hex')}`);
}

function verifyPassword(password, encodedHash) {
  const [scheme, salt, storedHash] = String(encodedHash || '').split('$');
  if (scheme !== 'scrypt' || !salt || !storedHash) return Promise.resolve(false);
  return scrypt(password, salt, 64).then((hash) => {
    const expected = Buffer.from(storedHash, 'hex');
    return expected.length === hash.length && crypto.timingSafeEqual(expected, hash);
  });
}

function normalizeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    name: row.name
  };
}

function getTokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function ensureRole(req, res, allowedRoles) {
  const role = req.user?.role;
  if (!role || (role !== 'admin' && !allowedRoles.includes(role))) {
    return res.status(403).json({ error: 'No tienes permisos para esta acción.' });
  }
  return null;
}

async function getCurrentUserFromHeader(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    req.user = null;
    req.tokenHash = null;
    if (token) {
      const tokenHash = getTokenHash(token);
      const record = await get(
        `SELECT users.* FROM sessions
         JOIN users ON users.id = sessions.userId
         WHERE sessions.tokenHash = ? AND sessions.expiresAt > ? AND users.isActive = 1;`,
        [tokenHash, new Date().toISOString()]
      );
      if (record) {
        req.user = normalizeUser(record);
        req.tokenHash = tokenHash;
      }
    }
    next();
  } catch (error) {
    next(error);
  }
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  }
  next();
}

app.use(getCurrentUserFromHeader);

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'stock-de-tienda-api', timestamp: new Date().toISOString() });
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
  }

  const now = Date.now();
  const attempts = loginAttempts.get(req.ip);
  if (attempts && attempts.blockedUntil > now) {
    return res.status(429).json({ error: 'Demasiados intentos. Espera 15 minutos e inténtalo de nuevo.' });
  }

  const user = await get('SELECT * FROM users WHERE username = ? AND isActive = 1;', [username]);
  const validPassword = user ? await verifyPassword(password, user.passwordHash) : false;

  if (!validPassword) {
    const nextAttempts = attempts && attempts.windowStartedAt > now - 15 * 60 * 1000
      ? attempts.count + 1
      : 1;
    loginAttempts.set(req.ip, {
      count: nextAttempts,
      windowStartedAt: attempts?.windowStartedAt > now - 15 * 60 * 1000 ? attempts.windowStartedAt : now,
      blockedUntil: nextAttempts >= 5 ? now + 15 * 60 * 1000 : 0
    });
    return res.status(401).json({ error: 'Credenciales inválidas.' });
  }

  loginAttempts.delete(req.ip);
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();
  await run('DELETE FROM sessions WHERE expiresAt <= ?;', [new Date().toISOString()]);
  await run(
    'INSERT INTO sessions (tokenHash, userId, expiresAt) VALUES (?, ?, ?);',
    [getTokenHash(token), user.id, expiresAt]
  );

  return res.json({
    user: normalizeUser(user),
    token,
    expiresAt
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/logout', requireAuth, async (req, res) => {
  await run('DELETE FROM sessions WHERE tokenHash = ?;', [req.tokenHash]);
  return res.json({ ok: true });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const currentPassword = typeof req.body.currentPassword === 'string' ? req.body.currentPassword : '';
  const newPassword = typeof req.body.newPassword === 'string' ? req.body.newPassword : '';

  if (newPassword.length < 12 || newPassword.length > 256) {
    return res.status(400).json({ error: 'La nueva contraseña debe tener entre 12 y 256 caracteres.' });
  }

  const user = await get('SELECT id, passwordHash FROM users WHERE id = ? AND isActive = 1;', [req.user.id]);
  if (!user || !(await verifyPassword(currentPassword, user.passwordHash))) {
    return res.status(401).json({ error: 'La contraseña actual es incorrecta.' });
  }
  if (await verifyPassword(newPassword, user.passwordHash)) {
    return res.status(400).json({ error: 'La nueva contraseña debe ser diferente a la actual.' });
  }

  const passwordHash = await hashPassword(newPassword);
  await run('UPDATE users SET password = ?, passwordHash = ? WHERE id = ?;', [
    '[stored as hash]',
    passwordHash,
    user.id
  ]);
  await run('DELETE FROM sessions WHERE userId = ?;', [user.id]);

  return res.json({ ok: true, message: 'Contraseña actualizada. Inicia sesión de nuevo.' });
});

app.post('/api/change-username', requireAuth, async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const currentPassword = typeof req.body.currentPassword === 'string' ? req.body.currentPassword : '';

  if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
    return res.status(400).json({ error: 'El usuario debe tener entre 3 y 32 caracteres: letras, números, punto, guion o guion bajo.' });
  }

  const user = await get('SELECT id, username, passwordHash, role, name FROM users WHERE id = ? AND isActive = 1;', [req.user.id]);
  if (!user || !(await verifyPassword(currentPassword, user.passwordHash))) {
    return res.status(401).json({ error: 'La contraseña actual es incorrecta.' });
  }
  if (username === user.username) {
    return res.status(400).json({ error: 'El nuevo usuario debe ser diferente al actual.' });
  }

  try {
    await run('UPDATE users SET username = ? WHERE id = ?;', [username, user.id]);
    return res.json({ user: normalizeUser({ ...user, username }) });
  } catch (error) {
    if (String(error.message).includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Ese usuario ya existe.' });
    }
    throw error;
  }
});

app.post('/api/users', requireAuth, async (req, res) => {
  const permissionError = ensureRole(req, res, ['admin']);
  if (permissionError) return permissionError;
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const name = String(req.body.name || '').trim();
  const role = String(req.body.role || '');
  if (!/^[a-z0-9._-]{3,32}$/.test(username) || password.length < 12 ||
      !name || name.length > 80 || !['admin', 'vendedor', 'contabilidad'].includes(role)) {
    return res.status(400).json({ error: 'Usuario, nombre, rol o contraseña inválidos. La contraseña debe tener al menos 12 caracteres.' });
  }
  try {
    const passwordHash = await hashPassword(password);
    await run(
      'INSERT INTO users (username, password, passwordHash, isActive, role, name) VALUES (?, ?, ?, 1, ?, ?);',
      [username, '[stored as hash]', passwordHash, role, name]
    );
    const user = await get('SELECT id, username, role, name FROM users WHERE username = ?;', [username]);
    return res.status(201).json(user);
  } catch (error) {
    if (String(error.message).includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Ese usuario ya existe.' });
    }
    throw error;
  }
});

app.get('/api/products', requireAuth, async (req, res) => {
  const products = await all('SELECT * FROM products ORDER BY brand, model');
  res.json(products);
});

app.post('/api/products', async (req, res) => {
  const permissionError = ensureRole(req, res, ['admin', 'contabilidad', 'vendedor']);
  if (permissionError) return permissionError;

  const payload = req.body || {};
  const brand = String(payload.brand || '').trim();
  const model = String(payload.model || '').trim();
  const storage = String(payload.storage || '').trim();
  const sku = String(payload.sku || '').trim();
  const price = Number(payload.price);
  const stock = Number(payload.stock);

  if (!brand || !model || !sku || !Number.isFinite(price) || !Number.isInteger(stock) || stock < 0) {
    return res.status(400).json({ error: 'Faltan datos o son inválidos.' });
  }

  const isSeller = req.user.role === 'vendedor';
  const id = isSeller
    ? `p-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    : payload.id || `p-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  try {
    if (isSeller) {
      await run(
        'INSERT INTO products (id, brand, model, storage, sku, price, stock) VALUES (?, ?, ?, ?, ?, ?, ?);',
        [id, brand, model, storage, sku, price, stock]
      );
    } else {
      await run(
        `INSERT INTO products (id, brand, model, storage, sku, price, stock)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           brand = excluded.brand,
           model = excluded.model,
           storage = excluded.storage,
           sku = excluded.sku,
           price = excluded.price,
           stock = excluded.stock;`,
        [id, brand, model, storage, sku, price, stock]
      );
    }

    const product = await get('SELECT * FROM products WHERE id = ?', [id]);
    return res.status(201).json(product);
  } catch (error) {
    return res.status(400).json({ error: error.message || 'No se pudo guardar el producto.' });
  }
});

app.put('/api/products/:id', async (req, res) => {
  const permissionError = ensureRole(req, res, ['admin', 'contabilidad']);
  if (permissionError) return permissionError;

  const existing = await get('SELECT * FROM products WHERE id = ?', [req.params.id]);
  if (!existing) {
    return res.status(404).json({ error: 'Producto no encontrado.' });
  }

  const payload = req.body || {};
  const brand = String(payload.brand || existing.brand).trim();
  const model = String(payload.model || existing.model).trim();
  const storage = String(payload.storage ?? existing.storage).trim();
  const sku = String(payload.sku || existing.sku).trim();
  const price = Number(payload.price ?? existing.price);
  const stock = Number(payload.stock ?? existing.stock);

  if (!brand || !model || !sku || !Number.isFinite(price) || !Number.isInteger(stock) || stock < 0) {
    return res.status(400).json({ error: 'Datos del producto inválidos.' });
  }

  await run(
    `UPDATE products SET brand = ?, model = ?, storage = ?, sku = ?, price = ?, stock = ? WHERE id = ?;`,
    [brand, model, storage, sku, price, stock, req.params.id]
  );

  const product = await get('SELECT * FROM products WHERE id = ?', [req.params.id]);
  return res.json(product);
});

app.delete('/api/products/:id', async (req, res) => {
  const permissionError = ensureRole(req, res, ['admin', 'contabilidad']);
  if (permissionError) return permissionError;

  const product = await get('SELECT * FROM products WHERE id = ?', [req.params.id]);
  if (!product) {
    return res.status(404).json({ error: 'Producto no encontrado.' });
  }

  await run('DELETE FROM products WHERE id = ?', [req.params.id]);
  return res.json({ ok: true, deleted: product.id });
});

app.get('/api/sales', requireAuth, async (req, res) => {
  const rows = await all('SELECT * FROM sales ORDER BY date DESC');
  res.json(rows.map((sale) => ({
    ...sale,
    devices: JSON.parse(sale.devices || '[]'),
    financing: JSON.parse(sale.financing || '{}'),
    creditContract: JSON.parse(sale.creditContract || '{}')
  })));
});

app.post('/api/sales', async (req, res) => {
  const permissionError = ensureRole(req, res, ['admin', 'vendedor']);
  if (permissionError) return permissionError;

  const payload = req.body || {};
  const saleId = payload.id || `s-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const invoiceNumber = payload.invoiceNumber || `F-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Date.now().toString(36).toUpperCase()}`;
  const brand = String(payload.brand || '').trim();
  const model = String(payload.model || '').trim();
  const storage = String(payload.storage || '').trim();
  const customer = String(payload.customer || '').trim();
  const unitPrice = Number(payload.unitPrice);
  const total = Number(payload.total);
  const devices = Array.isArray(payload.devices) ? payload.devices : [];
  const financing = payload.financing || { financed: false, downPayment: total, installmentCount: 0, installmentAmount: 0, paidAmount: total, payments: [] };
  const creditContract = payload.creditContract || {};

  if (!brand || !model || !customer || !Number.isFinite(unitPrice) || !Number.isFinite(total) || devices.length === 0) {
    return res.status(400).json({ error: 'La venta no tiene los datos mínimos necesarios.' });
  }

  const product = await get('SELECT * FROM products WHERE id = ?', [payload.productId]);
  if (!product) {
    return res.status(404).json({ error: 'Producto no encontrado.' });
  }

  if (product.stock < devices.length) {
    return res.status(400).json({ error: 'No hay suficiente stock para esta venta.' });
  }

  const saleDate = new Date().toISOString();

  await run(
    `INSERT INTO sales (id, invoiceNumber, date, brand, model, storage, customer, unitPrice, total, financing, creditContract, devices)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
    [saleId, invoiceNumber, saleDate, brand, model, storage, customer, unitPrice, total, JSON.stringify(financing), JSON.stringify(creditContract), JSON.stringify(devices)]
  );

  await run('UPDATE products SET stock = stock - ? WHERE id = ?', [devices.length, product.id]);

  const sale = await get('SELECT * FROM sales WHERE id = ?', [saleId]);
  return res.status(201).json({
    ...sale,
    devices: JSON.parse(sale.devices || '[]'),
    financing: JSON.parse(sale.financing || '{}'),
    creditContract: JSON.parse(sale.creditContract || '{}')
  });
});

app.post('/api/payments', async (req, res) => {
  const permissionError = ensureRole(req, res, ['admin', 'contabilidad']);
  if (permissionError) return permissionError;

  const saleId = String(req.body.saleId || '').trim();
  const amount = Number(req.body.amount);

  if (!saleId || !Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Monto del abono inválido.' });
  }

  const sale = await get('SELECT * FROM sales WHERE id = ?', [saleId]);
  if (!sale) {
    return res.status(404).json({ error: 'Venta no encontrada.' });
  }

  const financing = JSON.parse(sale.financing || '{}');
  const currentPaid = Number(financing.paidAmount || 0);
  const totalSale = Number(sale.total || 0);
  const outstanding = Math.max(0, totalSale - currentPaid);

  if (amount > outstanding) {
    return res.status(400).json({ error: 'El abono supera el saldo pendiente.' });
  }

  const payment = {
    date: new Date().toISOString(),
    amount,
    principalAmount: Math.min(amount, outstanding),
    lateFeeAmount: Math.max(0, amount - Math.min(amount, outstanding))
  };

  financing.paidAmount = Number(financing.paidAmount || 0) + payment.principalAmount;
  financing.payments = Array.isArray(financing.payments) ? [...financing.payments, payment] : [payment];

  await run('UPDATE sales SET financing = ? WHERE id = ?', [JSON.stringify(financing), saleId]);

  await run(
    `INSERT INTO payments (saleId, amount, principalAmount, lateFeeAmount, paymentDate)
     VALUES (?, ?, ?, ?, ?);`,
    [saleId, payment.amount, payment.principalAmount, payment.lateFeeAmount, payment.date]
  );

  return res.json({ ok: true, saleId, payment });
});

app.delete('/api/sales/:id', async (req, res) => {
  const permissionError = ensureRole(req, res, ['admin']);
  if (permissionError) return permissionError;

  const sale = await get('SELECT * FROM sales WHERE id = ?', [req.params.id]);
  if (!sale) {
    return res.status(404).json({ error: 'Venta no encontrada.' });
  }

  await run('DELETE FROM payments WHERE saleId = ?', [req.params.id]);
  await run('DELETE FROM sales WHERE id = ?', [req.params.id]);
  return res.json({ ok: true, deleted: sale.id });
});

async function setDeviceBlockedByImei(req, res, blocked) {
  const permissionError = ensureRole(req, res, ['admin', 'contabilidad']);
  if (permissionError) return permissionError;

  const imei = typeof req.body.imei === 'string' ? req.body.imei.trim() : '';
  if (!imei || imei.length > 40) {
    return res.status(400).json({ error: 'Ingresa un IMEI o número de serie válido.' });
  }

  const rows = await all('SELECT id, devices FROM sales;');
  const matches = [];
  for (const sale of rows) {
    const devices = JSON.parse(sale.devices || '[]');
    devices.forEach((device, index) => {
      if (String(device.code || '').trim().toLocaleLowerCase() === imei.toLocaleLowerCase()) {
        matches.push({ sale, devices, index });
      }
    });
  }

  if (matches.length === 0) {
    return res.status(404).json({ error: 'No se encontró un equipo registrado con ese IMEI o número de serie.' });
  }
  if (matches.length > 1) {
    return res.status(409).json({ error: 'El código aparece en más de un registro. Revisa los datos antes de cambiar su estado.' });
  }

  const [{ sale, devices, index }] = matches;
  const alreadyInRequestedState = Boolean(devices[index].blocked) === blocked;
  if (!alreadyInRequestedState) {
    devices[index] = { ...devices[index], blocked };
    await run('UPDATE sales SET devices = ? WHERE id = ?;', [JSON.stringify(devices), sale.id]);
  }

  return res.json({
    ok: true,
    imei: String(devices[index].code),
    blocked,
    alreadyInRequestedState
  });
}

app.post('/api/devices/block', (req, res) => setDeviceBlockedByImei(req, res, true));
app.post('/api/devices/unblock', (req, res) => setDeviceBlockedByImei(req, res, false));

app.post('/api/sales/:id/toggle-block', async (req, res) => {
  const permissionError = ensureRole(req, res, ['admin', 'contabilidad']);
  if (permissionError) return permissionError;

  const sale = await get('SELECT * FROM sales WHERE id = ?', [req.params.id]);
  if (!sale) {
    return res.status(404).json({ error: 'Venta no encontrada.' });
  }

  const devices = JSON.parse(sale.devices || '[]');
  const code = String(req.body.code || '').trim();
  if (!code) {
    return res.status(400).json({ error: 'Código requerido.' });
  }

  const nextDevices = devices.map((device) => (
    (String(device.code || '').toLowerCase() === code.toLowerCase())
      ? { ...device, blocked: !Boolean(device.blocked) }
      : device
  ));

  await run('UPDATE sales SET devices = ? WHERE id = ?', [JSON.stringify(nextDevices), sale.id]);
  return res.json({ ok: true, devices: nextDevices });
});

app.post('/api/reset-demo', async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Esta función solo está disponible en modo de desarrollo.' });
  }
  const permissionError = ensureRole(req, res, ['admin']);
  if (permissionError) return permissionError;

  await run('DELETE FROM payments;');
  await run('DELETE FROM sales;');
  await run('DELETE FROM products;');
  await seedDefaultProducts();

  return res.json({ ok: true, message: 'Datos de prueba restaurados.' });
});

app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Endpoint no encontrado.' });
  }
  return res.status(404).send('No encontrado.');
});

app.use((error, req, res, next) => {
  console.error('Error en la solicitud:', error);
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: 'Ocurrió un error interno. Inténtalo de nuevo.' });
});

async function startServer() {
  await initializeDatabase();
  app.listen(PORT, HOST, () => {
    console.log(`Servidor listo en http://${HOST}:${PORT}`);
  });
}

startServer().catch((error) => {
  console.error('No se pudo iniciar el servidor:', error);
  process.exit(1);
});
