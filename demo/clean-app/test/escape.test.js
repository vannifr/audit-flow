const test = require('node:test');
const assert = require('node:assert');
const { escapeHtml } = require('../src/escape');

test('escapes markup', () => {
  assert.strictEqual(escapeHtml('<b>"x"</b>'), '&lt;b&gt;&quot;x&quot;&lt;/b&gt;');
});
