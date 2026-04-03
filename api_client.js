'use strict';

const axios = require('axios');

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABLE: User-controlled URL passed directly to axios.get
// SSRF — attacker can redirect requests to internal services
// e.g. GET /api/fetch?url=http://169.254.169.254/latest/meta-data/
// ─────────────────────────────────────────────────────────────────────────────
async function fetchExternalData(req, res) {
  const targetUrl = req.query.url;    // USER INPUT ← SSRF risk
  try {
    const response = await axios.get(targetUrl);   // ← CVE-2023-45857
    res.json({ data: response.data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABLE: User-controlled payload forwarded via axios.post
// SSRF — attacker can craft the webhook URL to reach internal services
// ─────────────────────────────────────────────────────────────────────────────
async function sendWebhook(req, res) {
  const { webhookUrl, payload } = req.body;  // USER INPUT ← SSRF risk
  try {
    const result = await axios.post(webhookUrl, payload);  // ← CVE-2023-45857
    res.json({ status: result.status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SAFE: Hard-coded internal API URL (no user input)
// ─────────────────────────────────────────────────────────────────────────────
async function getHealthStatus() {
  const response = await axios.get('http://localhost:9090/health'); // safe
  return response.data;
}

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABLE: Using old CancelToken API — BREAKING in axios 1.x
// CancelToken was removed; replaced by AbortController
// ─────────────────────────────────────────────────────────────────────────────
function fetchWithCancel(url) {
  const source = axios.CancelToken.source();      // ← BREAKING in 1.x
  const promise = axios.get(url, {
    cancelToken: source.token,                     // ← BREAKING in 1.x
  });
  return { promise, cancel: source.cancel };
}

module.exports = { fetchExternalData, sendWebhook, getHealthStatus, fetchWithCancel };
