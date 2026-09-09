/*!
 * ScrubKit Engine — deterministic, reversible redaction of secrets & PII.
 * Zero dependencies. Runs identically in the browser and in Node.
 *
 * Design notes:
 *  - Every detector is a pure regex + optional validator. Validators (Luhn,
 *    IBAN mod-97, SSN structural rules) exist to kill false positives, which
 *    are the main reason naive redactors are unusable on real text.
 *  - Redaction is *consistent pseudonymization*: the same raw value always maps
 *    to the same placeholder within a document, so the text stays coherent for
 *    an LLM and the model's reply can be rehydrated afterwards.
 *  - Overlapping matches are resolved by (priority, length) so that e.g. a
 *    Postgres URL wins over the bare hostname inside it.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ScrubKit = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------- helpers

  function luhn(digits) {
    var sum = 0, alt = false;
    for (var i = digits.length - 1; i >= 0; i--) {
      var n = digits.charCodeAt(i) - 48;
      if (n < 0 || n > 9) return false;
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return digits.length > 0 && sum % 10 === 0;
  }

  function ibanValid(raw) {
    var s = raw.replace(/[\s-]/g, '').toUpperCase();
    if (s.length < 15 || s.length > 34) return false;
    s = s.slice(4) + s.slice(0, 4);
    var expanded = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c >= 65 && c <= 90) expanded += (c - 55);
      else if (c >= 48 && c <= 57) expanded += s[i];
      else return false;
    }
    // mod-97 over a long numeric string, chunked to stay in safe integer range
    var rem = 0;
    for (var j = 0; j < expanded.length; j++) {
      rem = (rem * 10 + (expanded.charCodeAt(j) - 48)) % 97;
    }
    return rem === 1;
  }

  function ssnValid(m) {
    var d = m.replace(/\D/g, '');
    if (d.length !== 9) return false;
    var area = d.slice(0, 3), group = d.slice(3, 5), serial = d.slice(5);
    if (area === '000' || area === '666' || area[0] === '9') return false;
    if (group === '00' || serial === '0000') return false;
    if (/^(\d)\1{8}$/.test(d)) return false;       // 111111111
    if (d === '123456789') return false;
    return true;
  }

  function isPrivateIPv4(ip) {
    var p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some(function (n) { return isNaN(n) || n > 255; })) return false;
    return p[0] === 10 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) ||
      p[0] === 0;
  }

  function validIPv4(ip) {
    var p = ip.split('.');
    if (p.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(p[i])) return false;
      var n = +p[i];
      if (n > 255) return false;
      if (p[i].length > 1 && p[i][0] === '0') return false;   // no leading zeros
    }
    return true;
  }

  // Entropy gate for "looks like a random secret" heuristics.
  function shannon(s) {
    var freq = Object.create(null), i;
    for (i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
    var h = 0;
    for (var k in freq) { var p = freq[k] / s.length; h -= p * Math.log2(p); }
    return h;
  }

  // ------------------------------------------------------------- detectors
  // priority: higher wins when two matches overlap.

  var DETECTORS = [
    // ---- private keys & certs -------------------------------------------
    { id: 'private_key', label: 'Private key', group: 'secret', priority: 100,
      re: /-----BEGIN[ A-Z0-9]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9]*PRIVATE KEY-----/g },
    { id: 'pgp_key', label: 'PGP private key', group: 'secret', priority: 100,
      re: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g },

    // ---- vendor-specific credentials (very low false-positive rate) ------
    { id: 'aws_access_key', label: 'AWS access key ID', group: 'secret', priority: 95,
      re: /\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[A-Z0-9]{16})\b/g },
    { id: 'aws_arn', label: 'AWS ARN', group: 'infra', priority: 70,
      re: /\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"'<>]+/g },
    { id: 'gh_token', label: 'GitHub token', group: 'secret', priority: 95,
      re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
    { id: 'openai_key', label: 'OpenAI API key', group: 'secret', priority: 95,
      re: /\b(sk-(?:proj|svcacct|admin)?-?[A-Za-z0-9_-]{20,})\b/g },
    { id: 'anthropic_key', label: 'Anthropic API key', group: 'secret', priority: 96,
      re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
    { id: 'google_api_key', label: 'Google API key', group: 'secret', priority: 95,
      re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { id: 'slack_token', label: 'Slack token', group: 'secret', priority: 95,
      re: /\bxox[baprse]-[A-Za-z0-9-]{10,}\b/g },
    { id: 'slack_webhook', label: 'Slack webhook', group: 'secret', priority: 95,
      re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/+_-]{20,}/g },
    { id: 'discord_webhook', label: 'Discord webhook', group: 'secret', priority: 95,
      re: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
    { id: 'stripe_key', label: 'Stripe key', group: 'secret', priority: 95,
      re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
    { id: 'twilio_sid', label: 'Twilio SID', group: 'secret', priority: 90,
      re: /\b(?:AC|SK)[0-9a-fA-F]{32}\b/g },
    { id: 'sendgrid_key', label: 'SendGrid key', group: 'secret', priority: 95,
      re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
    { id: 'npm_token', label: 'npm token', group: 'secret', priority: 95,
      re: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { id: 'pypi_token', label: 'PyPI token', group: 'secret', priority: 95,
      re: /\bpypi-[A-Za-z0-9_-]{50,}\b/g },
    { id: 'hf_token', label: 'Hugging Face token', group: 'secret', priority: 95,
      re: /\bhf_[A-Za-z0-9]{34,}\b/g },
    { id: 'gitlab_token', label: 'GitLab token', group: 'secret', priority: 95,
      re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
    { id: 'jwt', label: 'JWT', group: 'secret', priority: 92,
      re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },

    // ---- connection strings ---------------------------------------------
    { id: 'db_url', label: 'Database URL', group: 'secret', priority: 88,
      re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|clickhouse):\/\/[^\s"'<>`]+/gi },
    { id: 'basic_auth_url', label: 'URL with credentials', group: 'secret', priority: 88,
      re: /\bhttps?:\/\/[^\s:@\/]+:[^\s:@\/]+@[^\s"'<>`]+/g },

    // ---- generic assigned secrets (entropy-gated) ------------------------
    { id: 'assigned_secret', label: 'Assigned secret', group: 'secret', priority: 60,
      re: /\b((?:api[_-]?key|apikey|secret[_-]?key|secret|token|passwd|password|pwd|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*)(["'`]?)([^\s"'`,;]{8,})\2/gi,
      captureGroup: 3,
      validate: function (v) {
        if (/^(your|my|the|some|example|changeme|placeholder|xxx+|<.*>|\{\{.*\}\}|\$\{.*\}|null|none|true|false|undefined)$/i.test(v)) return false;
        if (/^\**$/.test(v) || /^\.+$/.test(v)) return false;
        if (/^(process\.env|os\.environ|env\.)/i.test(v)) return false;
        return shannon(v) >= 2.2;
      } },

    // ---- financial --------------------------------------------------------
    { id: 'credit_card', label: 'Payment card number', group: 'pii', priority: 85,
      re: /\b(?:\d[ -]*?){13,19}\b/g,
      validate: function (v) {
        var d = v.replace(/\D/g, '');
        if (d.length < 13 || d.length > 19) return false;
        if (/^(\d)\1+$/.test(d)) return false;
        if (!/^(4|5[1-5]|2(2[2-9]|[3-6]|7[01]|720)|3[47]|3(0[0-5]|[68])|6(011|5|4[4-9]|2)|8|9)/.test(d)) return false;
        return luhn(d);
      } },
    { id: 'iban', label: 'IBAN', group: 'pii', priority: 85,
      re: /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b/g,
      validate: ibanValid },
    { id: 'us_ssn', label: 'US SSN', group: 'pii', priority: 84,
      re: /\b\d{3}[- ]\d{2}[- ]\d{4}\b/g,
      validate: ssnValid },

    // ---- contact PII ------------------------------------------------------
    { id: 'email', label: 'Email address', group: 'pii', priority: 80,
      re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
      validate: function (v) {
        return !/@(example\.(com|org|net)|test\.com|localhost|domain\.com|email\.com|yourcompany\.com)$/i.test(v);
      } },
    { id: 'phone', label: 'Phone number', group: 'pii', priority: 72,
      re: /(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]\d{3,4}(?:[ .-]?\d{1,4})?/g,
      validate: function (v) {
        var d = v.replace(/\D/g, '');
        if (d.length < 9 || d.length > 15) return false;
        if (/^(\d)\1+$/.test(d)) return false;
        if (/^(19|20)\d{2}[-.]/.test(v)) return false;          // looks like a date
        return true;
      } },

    // ---- network / infra --------------------------------------------------
    { id: 'ipv4_public', label: 'Public IPv4', group: 'infra', priority: 68,
      re: /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
      validate: function (v) { return validIPv4(v) && !isPrivateIPv4(v); } },
    { id: 'ipv4_private', label: 'Private IPv4', group: 'infra', priority: 67, defaultOff: true,
      re: /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
      validate: function (v) { return validIPv4(v) && isPrivateIPv4(v); } },
    { id: 'ipv6', label: 'IPv6 address', group: 'infra', priority: 66,
      re: /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b/g },
    { id: 'mac', label: 'MAC address', group: 'infra', priority: 66,
      re: /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/g },
    { id: 'uuid', label: 'UUID', group: 'infra', priority: 40, defaultOff: true,
      re: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b/g }
  ];

  var DETECTOR_BY_ID = {};
  DETECTORS.forEach(function (d) { DETECTOR_BY_ID[d.id] = d; });

  // -------------------------------------------------------------- redaction

  function buildCustomDetectors(custom) {
    // custom: [{ id, label, pattern, flags, group }]  — user/team rule packs
    return (custom || []).map(function (c, i) {
      var flags = c.flags || 'g';
      if (flags.indexOf('g') === -1) flags += 'g';
      return {
        id: c.id || ('custom_' + i),
        label: c.label || 'Custom rule',
        group: c.group || 'custom',
        priority: typeof c.priority === 'number' ? c.priority : 90,
        re: new RegExp(c.pattern, flags),
        captureGroup: c.captureGroup
      };
    });
  }

  /**
   * redact(text, options) -> { text, map, findings, stats }
   *   options.enabled     : array of detector ids to run (default: all not defaultOff)
   *   options.custom      : array of custom rule objects
   *   options.placeholder : function(label, index, detectorId) -> string
   */
  function redact(text, options) {
    options = options || {};
    if (typeof text !== 'string') text = String(text == null ? '' : text);

    var active = DETECTORS.filter(function (d) {
      if (options.enabled) return options.enabled.indexOf(d.id) !== -1;
      return !d.defaultOff;
    }).concat(buildCustomDetectors(options.custom));

    // 1. collect candidate matches
    var candidates = [];
    active.forEach(function (d) {
      var re = new RegExp(d.re.source, d.re.flags);
      var m;
      while ((m = re.exec(text)) !== null) {
        if (m[0] === '') { re.lastIndex++; continue; }
        var value = m[0], start = m.index;
        if (d.captureGroup && m[d.captureGroup] !== undefined) {
          value = m[d.captureGroup];
          var off = m[0].lastIndexOf(value);
          start = m.index + (off === -1 ? 0 : off);
        }
        value = value.replace(/[\s.,;:]+$/, '');
        if (!value) continue;
        if (d.validate && !d.validate(value)) continue;
        candidates.push({
          det: d, value: value, start: start, end: start + value.length,
          priority: d.priority, len: value.length
        });
      }
    });

    // 2. resolve overlaps — highest priority wins, then longest match
    candidates.sort(function (a, b) {
      return (b.priority - a.priority) || (b.len - a.len) || (a.start - b.start);
    });
    var taken = [], accepted = [];
    candidates.forEach(function (c) {
      for (var i = 0; i < taken.length; i++) {
        if (c.start < taken[i][1] && c.end > taken[i][0]) return;   // overlaps
      }
      taken.push([c.start, c.end]);
      accepted.push(c);
    });

    // 3. assign stable placeholders (same raw value -> same token)
    var byValue = Object.create(null);
    var counters = Object.create(null);
    var map = Object.create(null);
    var mkPlaceholder = options.placeholder || function (label, idx, id) {
      return '[' + String(id).toUpperCase() + '_' + idx + ']';
    };

    accepted.sort(function (a, b) { return a.start - b.start; });
    accepted.forEach(function (c) {
      var key = c.det.id + ' ' + c.value;
      if (!byValue[key]) {
        counters[c.det.id] = (counters[c.det.id] || 0) + 1;
        var token = mkPlaceholder(c.det.label, counters[c.det.id], c.det.id);
        byValue[key] = token;
        map[token] = c.value;
      }
      c.token = byValue[key];
    });

    // 4. rebuild the string
    var out = '', cursor = 0;
    accepted.forEach(function (c) {
      out += text.slice(cursor, c.start) + c.token;
      cursor = c.end;
    });
    out += text.slice(cursor);

    // 5. summarise
    var stats = Object.create(null);
    accepted.forEach(function (c) {
      stats[c.det.id] = stats[c.det.id] || { label: c.det.label, group: c.det.group, count: 0 };
      stats[c.det.id].count++;
    });

    return {
      text: out,
      map: map,
      findings: accepted.map(function (c) {
        return { id: c.det.id, label: c.det.label, group: c.det.group,
                 value: c.value, token: c.token, start: c.start, end: c.end };
      }),
      stats: stats,
      count: accepted.length
    };
  }

  /** restore(text, map) — put the real values back into an LLM's reply. */
  function restore(text, map) {
    if (!map) return text;
    var tokens = Object.keys(map).sort(function (a, b) { return b.length - a.length; });
    var out = String(text);
    tokens.forEach(function (t) {
      out = out.split(t).join(map[t]);
    });
    return out;
  }

  return {
    version: '1.0.0',
    detectors: DETECTORS.map(function (d) {
      return { id: d.id, label: d.label, group: d.group, defaultOff: !!d.defaultOff };
    }),
    redact: redact,
    restore: restore,
    _internals: { luhn: luhn, ibanValid: ibanValid, ssnValid: ssnValid, shannon: shannon }
  };
});
