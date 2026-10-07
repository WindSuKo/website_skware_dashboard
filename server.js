const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

const API_SECRET = process.env.API_SECRET || 'KEYSECRETEBTWSKWARE';
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const KEYS_FILE = path.join(__dirname, 'data', 'keys.json');

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';
const GITHUB_FILE = process.env.GITHUB_FILE || 'data/keys.json';

const DAY = 86400000;
const DURATIONS = {
  '30s': 30 * 1000,
  'life': null,
  '1d': 1 * DAY,
  '3d': 3 * DAY,
  '7d': 7 * DAY,
  '1m': 30 * DAY,
  '3m': 90 * DAY
};

const readJSON = (f) => {
  try {
    const raw = fs.readFileSync(f, 'utf8').replace(/^\uFEFF/, '');
    const d = JSON.parse(raw);
    return Array.isArray(d) ? d : (d.users || d.keys || [d]);
  } catch (e) {
    console.error('[ERREUR] Lecture de ' + f + ' impossible :', e.message);
    return [];
  }
};

const writeJSON = (f, d) => {
  fs.writeFileSync(f + '.tmp', JSON.stringify(d, null, 2));
  fs.renameSync(f + '.tmp', f);

  if (f === KEYS_FILE) {
    syncKeysToGitHub();
  }
};

let githubSyncRunning = false;
let githubSyncQueued = false;

async function syncKeysToGitHub() {
  if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO || !GITHUB_FILE) {
    console.error('[GITHUB] Variables GitHub manquantes.');
    return;
  }

  if (githubSyncRunning) {
    githubSyncQueued = true;
    return;
  }

  githubSyncRunning = true;

  try {
    const content = fs.readFileSync(KEYS_FILE, 'utf8');

    const headers = {
      'Authorization': `Bearer ${GITHUB_TOKEN}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
      'User-Agent': 'SKWare-Panel'
    };

    const apiUrl = `https://api.github.com/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/contents/${GITHUB_FILE}`;

    let sha = null;

    const getResponse = await fetch(`${apiUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, {
      method: 'GET',
      headers
    });

    if (getResponse.ok) {
      const fileData = await getResponse.json();
      sha = fileData.sha;
    } else if (getResponse.status !== 404) {
      const errorText = await getResponse.text();
      throw new Error(`GET GitHub ${getResponse.status}: ${errorText}`);
    }

    const body = {
      message: 'Update keys.json',
      content: Buffer.from(content, 'utf8').toString('base64'),
      branch: GITHUB_BRANCH
    };

    if (sha) {
      body.sha = sha;
    }

    const putResponse = await fetch(apiUrl, {
      method: 'PUT',
      headers,
      body: JSON.stringify(body)
    });

    if (!putResponse.ok) {
      const errorText = await putResponse.text();
      throw new Error(`PUT GitHub ${putResponse.status}: ${errorText}`);
    }

    console.log('[GITHUB] keys.json synchronisé avec succès.');
  } catch (e) {
    console.error('[GITHUB] Synchronisation impossible :', e.message);
  } finally {
    githubSyncRunning = false;

    if (githubSyncQueued) {
      githubSyncQueued = false;
      syncKeysToGitHub();
    }
  }
}

function purgeExpired() {
  const keys = readJSON(KEYS_FILE);
  const alive = keys.filter(k => k.expiresAt === null || k.expiresAt > Date.now());

  if (alive.length !== keys.length) {
    writeJSON(KEYS_FILE, alive);
  }

  return alive;
}

function genKey(existing) {
  let k;

  do {
    const part = () => crypto.randomBytes(2).toString('hex').toUpperCase();
    k = `SKW-${part()}-${part()}-${part()}`;
  } while (existing.some(e => e.key === k));

  return k;
}

function createKey(duration, note = '') {
  const keys = purgeExpired();
  const now = Date.now();

  const entry = {
    key: genKey(keys),
    duration,
    note: String(note).slice(0, 60),
    createdAt: now,
    expiresAt: DURATIONS[duration] === null
      ? null
      : now + DURATIONS[duration]
  };

  keys.push(entry);

  writeJSON(KEYS_FILE, keys);

  return entry;
}

setInterval(purgeExpired, 5 * 1000);
purgeExpired();

const sessions = new Map();
const attempts = new Map();

const getCookie = (req, name) =>
  (req.headers.cookie || '')
    .split(';')
    .map(c => c.trim().split('='))
    .find(c => c[0] === name)?.[1];

function getSession(req) {
  const t = getCookie(req, 'sid');
  const s = t && sessions.get(t);

  if (!s || s.exp < Date.now()) {
    if (t) sessions.delete(t);
    return null;
  }

  return s;
}

const auth = (req, res, next) =>
  getSession(req)
    ? next()
    : res.status(401).json({ error: 'Non connecté' });

const safeEq = (a, b) => {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const a = attempts.get(ip) || { n: 0, until: 0 };

  if (a.until > Date.now()) {
    return res.status(429).json({
      error: 'Trop de tentatives, réessaie dans 1 minute.'
    });
  }

  const { email, password } = req.body || {};
  const users = readJSON(USERS_FILE);

  const user = users.find(
    u =>
      u &&
      String(u.email).trim().toLowerCase() ===
      String(email || '').trim().toLowerCase()
  );

  if (!user) {
    console.log(
      '[LOGIN] email inconnu. Utilisateurs chargés :',
      users.length,
      '| fichier :',
      USERS_FILE
    );
  }

  if (!user || !safeEq(String(user.password), password || '')) {
    a.n++;

    if (a.n >= 5) {
      a.n = 0;
      a.until = Date.now() + 60000;
    }

    attempts.set(ip, a);

    return res.status(401).json({
      error: 'Email ou mot de passe incorrect.'
    });
  }

  attempts.delete(ip);

  const token = crypto.randomBytes(32).toString('hex');

  sessions.set(token, {
    email: user.email,
    exp: Date.now() + 12 * 3600000
  });

  res.setHeader(
    'Set-Cookie',
    `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`
  );

  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  sessions.delete(getCookie(req, 'sid'));

  res.setHeader(
    'Set-Cookie',
    'sid=; HttpOnly; Path=/; Max-Age=0'
  );

  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) =>
  res.json({
    email: getSession(req).email
  })
);

app.get('/api/keys', auth, (req, res) =>
  res.json(
    purgeExpired().sort(
      (a, b) => b.createdAt - a.createdAt
    )
  )
);

app.post('/api/keys', auth, (req, res) => {
  const { duration, note } = req.body || {};

  if (!(duration in DURATIONS)) {
    return res.status(400).json({
      error: 'Durée invalide (30s, 1d, 3d, 7d, 1m, 3m, life)'
    });
  }

  res.status(201).json(createKey(duration, note));
});

app.put('/api/keys/:key', auth, (req, res) => {
  const keys = purgeExpired();
  const k = keys.find(x => x.key === req.params.key);

  if (!k) {
    return res.status(404).json({
      error: 'Clé introuvable'
    });
  }

  const { duration, note } = req.body || {};

  if (duration) {
    if (!(duration in DURATIONS)) {
      return res.status(400).json({
        error: 'Durée invalide'
      });
    }

    k.duration = duration;

    k.expiresAt =
      DURATIONS[duration] === null
        ? null
        : Date.now() + DURATIONS[duration];
  }

  if (note !== undefined) {
    k.note = String(note).slice(0, 60);
  }

  writeJSON(KEYS_FILE, keys);

  res.json(k);
});

app.delete('/api/keys/:key', auth, (req, res) => {
  const keys = purgeExpired();

  const rest = keys.filter(
    x => x.key !== req.params.key
  );

  if (rest.length === keys.length) {
    return res.status(404).json({
      error: 'Clé introuvable'
    });
  }

  writeJSON(KEYS_FILE, rest);

  res.json({
    ok: true
  });
});

app.post('/api/generate', (req, res) => {
  if (!safeEq(
    req.headers['x-api-secret'] || '',
    API_SECRET
  )) {
    return res.status(401).json({
      error: 'Secret invalide'
    });
  }

  const { duration = '1d', note } = req.body || {};

  if (!(duration in DURATIONS)) {
    return res.status(400).json({
      error: 'Durée invalide (30s, 1d, 3d, 7d, 1m, 3m, life)'
    });
  }

  res.status(201).json(
    createKey(duration, note)
  );
});

app.post('/api/verify', (req, res) => {
  const k = purgeExpired().find(
    x =>
      x.key === String(
        (req.body || {}).key || ''
      ).toUpperCase()
  );

  res.json(
    k
      ? {
          valid: true,
          expiresAt: k.expiresAt
        }
      : {
          valid: false
        }
  );
});

app.get(
  ['/dashboard', '/dashboard.html'],
  (req, res) =>
    getSession(req)
      ? res.sendFile(
          path.join(
            __dirname,
            'views',
            'dashboard.html'
          )
        )
      : res.redirect('/login.html')
);

app.get('/login.html', (req, res, next) =>
  getSession(req)
    ? res.redirect('/dashboard')
    : next()
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

app.listen(PORT, () =>
  console.log(
    `SKWARE panel -> http://localhost:${PORT}`
  )
);