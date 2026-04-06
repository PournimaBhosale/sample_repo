'use strict';

const mkdirp = require('mkdirp');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// TRANSITIVE VULN: mkdirp@0.5.5 depends on minimist@1.2.5
// minimist < 1.2.6 is vulnerable to Prototype Pollution (CVE-2021-44906)
// mkdirp itself is safe, but it brings in the vulnerable minimist transitively.
//
// Resolution options:
//   1. Upgrade mkdirp to 1.x+ (drops minimist dependency entirely)
//   2. Add "overrides" / "resolutions" in package.json to force minimist 1.2.6+
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create upload directory — uses mkdirp which transitively pulls in minimist
 */
function ensureUploadDir(userId) {
  const dir = path.join('/tmp/uploads', userId);   // userId from req.params
  return mkdirp(dir);                               // ← transitive CVE-2021-44906
}

/**
 * Create nested temp directory
 */
function createTempDir(subpath) {
  const dir = path.join('/tmp/work', subpath);      // subpath from config
  return mkdirp(dir);
}

module.exports = { ensureUploadDir, createTempDir };
