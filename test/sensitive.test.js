/* Auren - classifier tests for outgoing form data.
 *
 * Run: npm run test:unit (this file is required by test/unit.test.js's runner
 * via a separate entry; see package.json). Focus: obvious false positives and
 * false negatives on representative payloads.
 */
'use strict';
const assert = require('assert');
const { classifySensitivePayload, luhnValid } = require('../src/core/sensitive');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try { fn(); passed += 1; console.log('  ok   ' + name); }
  catch (err) { failed += 1; console.error('  FAIL ' + name); console.error('       ' + (err && err.stack || err.message)); }
}

function typesOf(input) { return classifySensitivePayload(input).types; }
function has(input, type) { return typesOf(input).includes(type); }

console.log('sensitive classifier — SSN');
test('detects dashed SSN', () => {
  assert.ok(has({ ssn: '123-45-6789' }, 'ssn'));
  assert.ok(has('ssn=123-45-6789', 'ssn'));
});
test('does not flag a phone number as SSN', () => {
  assert.ok(!has({ phone: '555-123-4567' }, 'ssn'));
});
test('does not flag an arbitrary 9-digit id without SSN shape', () => {
  assert.ok(!has({ id: '123456789' }, 'ssn'));
  assert.ok(has({ ssn: '123456789' }, 'ssn'), '9-digit value under an ssn key counts');
});

console.log('sensitive classifier — credit card');
test('detects valid Luhn card numbers (compact and spaced)', () => {
  assert.ok(has({ card: '4111111111111111' }, 'credit_card'));
  assert.ok(has({ cc: '4111 1111 1111 1111' }, 'credit_card'));
  assert.ok(has({ pan: '4111-1111-1111-1111' }, 'credit_card'));
});
test('detects a card number inside a raw body string', () => {
  assert.ok(has('cardnumber=4111111111111111&name=A', 'credit_card'));
});
test('rejects a number that fails Luhn', () => {
  assert.ok(!has({ card: '4111111111111112' }, 'credit_card'));
  assert.ok(!has({ note: 'my lucky number is 1234567890123456' }, 'credit_card'));
});
test('Luhn checksum is correct on known vectors', () => {
  assert.ok(luhnValid('4111111111111111'));
  assert.ok(luhnValid('5555555555554444'));
  assert.ok(luhnValid('378282246310005'));
  assert.ok(!luhnValid('4111111111111112'));
});

console.log('sensitive classifier — passwords / secrets');
test('flags password fields and email+password combos', () => {
  assert.ok(has({ password: 'hunter2' }, 'password'));
  assert.ok(has({ user_password: 'hunter2' }, 'password'));
  assert.ok(has({ email: 'a@example.com', password: 'hunter2' }, 'email_password'));
  assert.ok(has({ username: 'alice', pwd: 'x' }, 'email_password'));
});
test('flags API token shapes as secrets', () => {
  assert.ok(has({ token: 'sk-live-abcdefghijklmnopqrstuvwxyz123456' }, 'secret'));
  assert.ok(has({ key: 'AKIAIOSFODNN7EXAMPLE' }, 'secret'));
  assert.ok(has({ auth: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij' }, 'secret'));
});
test('does not flag password alone as email+password', () => {
  const t = typesOf({ password: 'hunter2' });
  assert.ok(!t.includes('email_password'));
});

console.log('sensitive classifier — benign inputs');
test('benign payloads are not flagged', () => {
  assert.ok(!classifySensitivePayload({ username: 'alice', city: 'Paris' }).sensitive);
  assert.ok(!classifySensitivePayload({ q: 'best restaurants near me' }).sensitive);
  assert.ok(!classifySensitivePayload('name=John&city=Paris&age=42').sensitive);
  assert.ok(!classifySensitivePayload({ email: 'a@example.com' }).sensitive, 'email alone is not sensitive');
  assert.ok(!classifySensitivePayload('').sensitive);
  assert.ok(!classifySensitivePayload(null).sensitive);
});
test('email+password needs BOTH sides', () => {
  assert.ok(!has({ email: 'a@example.com', secretanswer: 'mothers-maiden' }, 'email_password'));
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
