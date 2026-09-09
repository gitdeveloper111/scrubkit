const S = require('./scrubkit.js');
let pass = 0, fail = 0;
const failures = [];

function t(name, fn) {
  try { fn(); pass++; }
  catch (e) { fail++; failures.push(name + ' :: ' + e.message); }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

function hits(text, id, opts) {
  return S.redact(text, opts).findings.filter(f => f.id === id);
}

// ---------------------------------------------------------------- POSITIVES

t('AWS access key', () => assert(hits('key ' + 'AKIA' + 'IOSFODNN7EXAMPLE here', 'aws_access_key').length === 1));
t('GitHub PAT', () => assert(hits('ghp_' + 'a'.repeat(36), 'gh_token').length === 1));
t('Anthropic key', () => assert(hits('sk-ant-api03-' + 'x'.repeat(30), 'anthropic_key').length === 1));
t('Google API key', () => assert(hits('AIza' + 'B'.repeat(35), 'google_api_key').length === 1));
t('Slack token', () => assert(hits('xox' + 'b-123456789012-abcdefghijkl', 'slack_token').length === 1));
t('Stripe live key', () => assert(hits('sk_live_' + 'a'.repeat(24), 'stripe_key').length === 1));
t('JWT', () => assert(hits(
  'eyJ' + 'hbGciOiJIUzI1NiJ9.' + 'eyJ' + 'zdWIiOiIxMjM0NTY3ODkwIn0.' + 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', 'jwt').length === 1));
t('Private key block', () => assert(hits(
  '-----BEGIN RSA ' + 'PRIVATE KEY-----\nMIIEow\n-----END RSA ' + 'PRIVATE KEY-----', 'private_key').length === 1));
t('Postgres URL', () => assert(hits('postgres://' + 'admin:hunter2@db.internal:5432/prod', 'db_url').length === 1));
t('Mongo srv URL', () => assert(hits('mongodb+srv://u:p@cluster0.abc.mongodb.net/app', 'db_url').length === 1));
t('Email', () => assert(hits('ping alice.smith@acme-corp.io ok', 'email').length === 1));
t('Public IPv4', () => assert(hits('host 52.94.236.248 responded', 'ipv4_public').length === 1));
t('MAC address', () => assert(hits('nic 3C:22:FB:1A:9D:0E up', 'mac').length === 1));
t('Visa card (Luhn valid)', () => assert(hits('card 4111 1111 1111 1111 ok', 'credit_card').length === 1));
t('Amex (Luhn valid)', () => assert(hits('amex 378282246310005 charged', 'credit_card').length === 1));
t('IBAN (mod-97 valid)', () => assert(hits('iban GB82WEST12345698765432 sent', 'iban').length === 1));
t('US SSN', () => assert(hits('ssn 536-90-4432 on file', 'us_ssn').length === 1));
t('Assigned secret', () => assert(hits('API_KEY = "8fj39dKs02mzQ1xR"', 'assigned_secret').length === 1));
t('Slack webhook', () => assert(hits(
  'https://hooks.slack.com/services/' + 'T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX', 'slack_webhook').length === 1));
t('AWS ARN', () => assert(hits('arn:aws:iam::123456789012:role/AdminRole', 'aws_arn').length === 1));
t('URL with credentials', () => assert(hits('https://bob:s3cr3t@git.internal/repo.git', 'basic_auth_url').length === 1));

// -------------------------------------------------------- FALSE POSITIVES
// These are the cases that make naive redactors unusable.

t('Version number is not a phone', () => assert(hits('upgraded to 1.22.310 today', 'phone').length === 0));
t('Date is not a phone', () => assert(hits('released 2026-03-14 stable', 'phone').length === 0));
t('Semver is not an IP', () => assert(hits('node v22.22.2.1 build', 'ipv4_public').length === 0));
t('Invalid octet is not an IP', () => assert(hits('id 999.1.1.1 bad', 'ipv4_public').length === 0));
t('Private IP off by default', () => assert(hits('server 192.168.1.10 local', 'ipv4_public').length === 0));
t('Luhn-invalid card ignored', () => assert(hits('num 4111 1111 1111 1112 nope', 'credit_card').length === 0));
t('Repeated digits not a card', () => assert(hits('0000000000000000 filler', 'credit_card').length === 0));
t('Order id not a card', () => assert(hits('order 12345678901234567 shipped', 'credit_card').length === 0));
t('Invalid SSN area 000', () => assert(hits('code 000-12-3456 ref', 'us_ssn').length === 0));
t('Known-dummy SSN rejected', () => assert(hits('ssn 123-45-6789', 'us_ssn').length === 0));
t('Repeated SSN rejected', () => assert(hits('ssn 111-11-1111', 'us_ssn').length === 0));
t('Invalid IBAN checksum', () => assert(hits('iban GB82WEST12345698765433 x', 'iban').length === 0));
t('example.com email ignored', () => assert(hits('mail to user@example.com', 'email').length === 0));
t('env var reference not a secret', () => assert(hits('api_key = process.env.API_KEY', 'assigned_secret').length === 0));
t('placeholder not a secret', () => assert(hits('password = "changeme"', 'assigned_secret').length === 0));
t('masked value not a secret', () => assert(hits('token: "********"', 'assigned_secret').length === 0));
t('templated value not a secret', () => assert(hits('secret = "${VAULT_SECRET}"', 'assigned_secret').length === 0));
t('low-entropy value not a secret', () => assert(hits('password = "aaaaaaaaaa"', 'assigned_secret').length === 0));
t('UUID off by default', () => assert(hits('id 550e8400-e29b-41d4-a716-446655440000', 'uuid').length === 0));

// ------------------------------------------------------ ROUND-TRIP / CORE

t('round-trip restores exactly', () => {
  const src = 'Email alice@acme.io from 52.94.236.248 using ghp_' + 'z'.repeat(36) + ' now.';
  const r = S.redact(src);
  assert(r.count === 3, 'expected 3 findings, got ' + r.count);
  assert(S.restore(r.text, r.map) === src, 'round trip mismatch');
});

t('same value gets same token', () => {
  const r = S.redact('a@x.io talked to b@x.io and a@x.io again');
  const toks = r.findings.map(f => f.token);
  assert(toks[0] === toks[2], 'repeat value should reuse token');
  assert(toks[0] !== toks[1], 'distinct values need distinct tokens');
  assert(Object.keys(r.map).length === 2, 'map should hold 2 entries');
});

t('redacted text contains no raw secret', () => {
  const secret = 'ghp_' + 'q'.repeat(36);
  const r = S.redact('token is ' + secret);
  assert(r.text.indexOf(secret) === -1, 'secret leaked into output');
});

t('restore survives LLM-style rewrapping', () => {
  const src = 'Contact carol@acme.io about host 52.94.236.248.';
  const r = S.redact(src);
  const reply = 'Sure — I would email ' + r.findings[0].token +
                ' and then check ' + r.findings[1].token + ' for logs.';
  const back = S.restore(reply, r.map);
  assert(back.indexOf('carol@acme.io') !== -1 && back.indexOf('52.94.236.248') !== -1);
});

t('overlap: db URL wins over inner email-ish/host', () => {
  const r = S.redact('postgres://' + 'admin:hunter2@db.internal:5432/prod');
  assert(r.count === 1 && r.findings[0].id === 'db_url', 'got ' + JSON.stringify(r.findings.map(f=>f.id)));
});

t('custom rule pack works', () => {
  const r = S.redact('ticket ACME-4821 filed', {
    custom: [{ id: 'jira', label: 'Jira key', pattern: '\\bACME-\\d{3,6}\\b' }]
  });
  assert(r.count === 1 && r.findings[0].id === 'jira');
});

t('enabled list restricts detectors', () => {
  const r = S.redact('a@b.io and 52.94.236.248', { enabled: ['email'] });
  assert(r.count === 1 && r.findings[0].id === 'email');
});

t('empty and non-string input safe', () => {
  assert(S.redact('').count === 0);
  assert(S.redact(null).text === '');
  assert(S.restore('x', null) === 'x');
});

t('idempotent on already-redacted text', () => {
  const r1 = S.redact('mail a@b.io now');
  const r2 = S.redact(r1.text);
  assert(r2.count === 0, 'placeholders should not be re-detected');
});

t('large input completes', () => {
  const big = ('lorem ipsum dolor sit amet consectetur 12345 '.repeat(4000)) + ' a@b.io';
  const start = Date.now();
  const r = S.redact(big);
  const ms = Date.now() - start;
  assert(r.count >= 1, 'should still find the email');
  assert(ms < 6000, 'too slow: ' + ms + 'ms');
});

// ----------------------------------------------------- REALISTIC DOCUMENT

t('realistic mixed document', () => {
  const doc = [
    'Hi team — prod is throwing 500s.',
    'DB: postgres://' + 'svc_api:Xj4%40kLp9@prod-db-01.internal:5432/orders',
    'Affected user: maria.gonzalez@northwind-logistics.com (phone +1 415-555-0142)',
    'Her card on file ends badly: 5555 5555 5555 4444',
    'Deploy ran from 52.94.236.248 with token ghp_' + 'k'.repeat(36),
    'AWS role arn:aws:iam::123456789012:role/DeployBot',
    'See ticket at https://example.com/docs and version 3.11.9 of the runtime.'
  ].join('\n');

  const r = S.redact(doc);
  const ids = Object.keys(r.stats);

  ['db_url', 'email', 'credit_card', 'ipv4_public', 'gh_token', 'aws_arn']
    .forEach(id => assert(ids.indexOf(id) !== -1, 'missed ' + id));

  assert(r.text.indexOf('maria.gonzalez@northwind-logistics.com') === -1, 'email leaked');
  assert(r.text.indexOf('5555 5555 5555 4444') === -1, 'card leaked');
  assert(r.text.indexOf('prod-db-01.internal') === -1, 'db url leaked');
  assert(r.text.indexOf('3.11.9') !== -1, 'version number should survive');
  assert(S.restore(r.text, r.map) === doc, 'round trip failed on realistic doc');
});

// ------------------------------------------------------------------ REPORT

console.log('\n  ScrubKit engine v' + S.version);
console.log('  ' + pass + ' passed, ' + fail + ' failed\n');
if (fail) { failures.forEach(f => console.log('   FAIL  ' + f)); process.exit(1); }
