
const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));

// DATABASE CONNECTION
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.PGSSL === "false"
      ? false
      : { rejectUnauthorized: false }
});

// ENVIRONMENT VARIABLES
const secret = process.env.SESSION_SECRET;
const operatorPassword = process.env.OPERATOR_PASSWORD;

if (!process.env.DATABASE_URL || !secret || !operatorPassword) {
  throw new Error(
    "Set DATABASE_URL, SESSION_SECRET and OPERATOR_PASSWORD"
  );
}

// SECURITY HELPERS
const h = (x) =>
  crypto
    .createHmac("sha256", secret)
    .update(x)
    .digest("base64url");

const token = (role, code, ttl = 86400) => {
  const payload = Buffer.from(
    JSON.stringify({
      role,
      code,
      exp: Date.now() + ttl * 1000
    })
  ).toString("base64url");

  return payload + "." + h(payload);
};

// AUTHENTICATION
function auth(req, res, next) {
  try {
    const [payload, sig] = (req.headers.authorization || "")
      .replace(/^Bearer /, "")
      .split(".");

    if (!payload || !sig) {
      throw new Error("Missing token");
    }

    const expected = Buffer.from(h(payload));
    const received = Buffer.from(sig);

    if (
      expected.length !== received.length ||
      !crypto.timingSafeEqual(expected, received)
    ) {
      throw new Error("Invalid token");
    }

    const p = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (p.exp < Date.now()) {
      throw new Error("Expired token");
    }

    req.auth = p;
    next();
  } catch (e) {
    res.status(401).json({
      error: "Sign in again"
    });
  }
}

// RESEARCHER ACCESS
const admin = (req, res, next) => {
  if (req.auth.role === "admin") {
    return next();
  }

  return res.status(403).json({
    error: "Researcher only"
  });
};

// NORMALIZE PARTICIPANT CODE
const safeCode = (s) =>
  String(s || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");

// RESEARCHER LOGIN
app.post("/api/operator/login", (req, res) => {
  const a = Buffer.from(
    String(req.body.password || "")
  );

  const b = Buffer.from(operatorPassword);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return res.status(401).json({
      error: "Incorrect password"
    });
  }

  res.json({
    token: token("admin", "", 8 * 3600)
  });
});

// PARTICIPANT LOGIN
// ONLY PARTICIPANT CODE IS REQUIRED
// NO PASSWORD OR PIN
app.post("/api/participant/login", async (req, res) => {
  const code = safeCode(req.body.code);

  const { rows } = await pool.query(
    "SELECT data FROM participants WHERE code=$1",
    [code]
  );

  if (!rows.length) {
    return res.status(401).json({
      error: "Invalid participant code"
    });
  }

  res.json({
    token: token("participant", code, 30 * 86400),
    participant: rows[0].data
  });
});

// GET ALL PARTICIPANTS
// RESEARCHER ONLY
app.get("/api/participants", auth, admin, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT data FROM participants ORDER BY created_at"
  );

  res.json(rows.map((r) => r.data));
});

// CREATE NEW PARTICIPANT
// NO PARTICIPANT PIN GENERATED
app.post("/api/participants", auth, admin, async (req, res) => {
  const code = safeCode(req.body.code);
  const group = Number(req.body.group);

  if (
    !/^[A-Z0-9_-]{2,32}$/.test(code) ||
    ![1, 2, 3, 4].includes(group)
  ) {
    return res.status(400).json({
      error: "Invalid code or group"
    });
  }

  const data = {
    code: code,
    group: group,
    createdAt: new Date().toISOString(),
    profile: null,
    days: [],
    trials: [],
    events: [],
    lhs: null
  };

  try {
    // Random placeholder keeps existing database compatible.
    // Participants never use this value.
    const unusedHash = h(
      crypto.randomBytes(32).toString("hex")
    );

    await pool.query(
      "INSERT INTO participants(code,pin_hash,data) VALUES($1,$2,$3)",
      [code, unusedHash, data]
    );

    res.json({
      participant: data
    });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({
        error: "Code already exists"
      });
    }

    throw e;
  }
});

// UPDATE PARTICIPANT PROGRESS
app.put("/api/participants/:code", auth, async (req, res) => {
  const code = safeCode(req.params.code);

  if (
    req.auth.role !== "admin" &&
    req.auth.code !== code
  ) {
    return res.status(403).json({
      error: "Forbidden"
    });
  }

  const existing = await pool.query(
    "SELECT data FROM participants WHERE code=$1",
    [code]
  );

  if (!existing.rows.length) {
    return res.status(404).json({
      error: "Unknown participant"
    });
  }

  const old = existing.rows[0].data;
  const data = req.body;

  if (
    !data ||
    data.code !== code ||
    JSON.stringify(data).length > 1500000
  ) {
    return res.status(400).json({
      error: "Invalid participant data"
    });
  }

  // Participants cannot change their research group.
  if (
    req.auth.role !== "admin" &&
    data.group !== old.group
  ) {
    return res.status(403).json({
      error: "Cannot change group"
    });
  }

  await pool.query(
    "UPDATE participants SET data=$2 WHERE code=$1",
    [code, data]
  );

  res.json({
    ok: true
  });
});

// HEALTH CHECK
app.get("/api/health", (_req, res) => {
  res.json({
    ok: true
  });
});

// SERVE EXPERIMENT WEBSITE
app.use(express.static("public"));

// ERROR HANDLER
app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "Server error"
  });
});

// CREATE DATABASE TABLE IF NECESSARY
// START SERVER
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS participants (
      code TEXT PRIMARY KEY,
      pin_hash TEXT NOT NULL,
      data JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  app.listen(
    process.env.PORT || 3000,
    () => {
      console.log("Cloud study ready");
    }
  );
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
