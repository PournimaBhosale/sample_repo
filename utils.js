'use strict';

const _ = require('lodash');

/**
 * VULNERABLE: caller can pass user-controlled `override`
 * e.g. mergeConfigs(defaultConfig, req.body)
 *
 * @param {object} base     - Trusted base configuration
 * @param {object} override - Potentially user-supplied overrides ← risk
 * @returns {object}
 */
function mergeConfigs(base, override) {
  return _.merge({}, base, override);  // ← CVE-2020-8203
}

/**
 * SAFE: _.groupBy is not affected by prototype pollution
 */
function groupItems(items, key) {
  return _.groupBy(items, key);
}

/**
 * SAFE: _.flattenDeep is not in the affected function list
 */
function flattenNested(arr) {
  return _.flattenDeep(arr);
}

/**
 * VULNERABLE: keys/values arrays could originate from user input
 * _.zipObjectDeep is listed in the Snyk advisory
 *
 * @param {string[]} keys   - May be user-supplied ← risk
 * @param {any[]}    values
 * @returns {object}
 */
function buildNestedObject(keys, values) {
  return _.zipObjectDeep(keys, values);  // ← CVE-2020-8203
}

module.exports = { mergeConfigs, groupItems, flattenNested, buildNestedObject };
