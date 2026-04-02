'use strict';

const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABLE: req.body is user-controlled input passed directly to _.merge
// An attacker can send {"__proto__":{"isAdmin":true}} to pollute Object.prototype
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/config', (req, res) => {
  const defaults = { timeout: 3000, retries: 3, debug: false };
  const config = _.merge({}, defaults, req.body);   // ← CVE-2020-8203 risk
  res.json({ config });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABLE: req.body.options is user-controlled and reaches _.defaultsDeep
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/user/preferences', (req, res) => {
  const basePrefs = { theme: 'light', language: 'en', notifications: true };
  const prefs = _.defaultsDeep({}, req.body.options, basePrefs); // ← risk
  res.json({ preferences: prefs });
});

// ─────────────────────────────────────────────────────────────────────────────
// SAFE: no user input involved — only internal server data merged
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/info', (_req, res) => {
  const serverInfo = { version: '1.0.0', name: 'my-app' };
  const extra = { uptime: process.uptime() };
  const info = _.merge({}, serverInfo, extra);   // ← safe (no user input)
  res.json(info);
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
