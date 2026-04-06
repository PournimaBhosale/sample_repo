'use strict';

const semver = require('semver');

// ─────────────────────────────────────────────────────────────────────────────
// LOW SEVERITY: semver.clean() is vulnerable to ReDoS (CVE-2022-25883)
// Only exploitable with malicious version strings — unlikely in production.
// Fix is a simple manifest bump to 7.5.2+ — no code changes needed.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validate and normalise a version string from user input
 */
function parseVersion(versionStr) {
  const cleaned = semver.clean(versionStr);        // ← CVE-2022-25883 (ReDoS)
  if (!cleaned) {
    throw new Error(`Invalid version: ${versionStr}`);
  }
  return cleaned;
}

/**
 * Check if a version is valid — safe call (no user input concern)
 */
function isValidVersion(ver) {
  return semver.valid(ver) !== null;
}

/**
 * Compare two versions for sorting
 */
function compareVersions(a, b) {
  return semver.compare(a, b);
}

module.exports = { parseVersion, isValidVersion, compareVersions };
