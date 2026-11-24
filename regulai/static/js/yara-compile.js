/*
 * YARA rule compile / test helpers for the Rules pages.
 *
 * Endpoints return JSON:
 *   { ok, error, rules: [identifier], tested, matched,
 *     matches: [{rule, identifier, data, offset}], truncated }
 */
(function () {
  'use strict';

  function getCsrfToken() {
    const input = document.querySelector('input[name="csrfmiddlewaretoken"]');
    if (input) return input.value;
    const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  async function postForm(url, fields) {
    const body = new URLSearchParams();
    Object.keys(fields).forEach(function (key) {
      if (fields[key] !== undefined && fields[key] !== null) body.append(key, fields[key]);
    });
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'X-CSRFToken': getCsrfToken(),
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      },
      credentials: 'same-origin',
      body: body,
    });
    if (!response.ok) {
      let message = 'HTTP ' + response.status;
      try {
        const data = await response.json();
        if (data && (data.error || data.message)) message = data.error || data.message;
      } catch (e) { /* not JSON */ }
      throw new Error(message);
    }
    return response.json();
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      if (key === 'text') node.textContent = attrs[key];
      else node.setAttribute(key, attrs[key]);
    });
    (children || []).forEach(function (child) { if (child) node.appendChild(child); });
    return node;
  }

  /* Renders a full result (compile + optional test) into a container. */
  function renderResult(container, result) {
    container.replaceChildren();

    if (!result.ok) {
      container.appendChild(el('div', { class: 'alert alert-danger mb-0 small' }, [
        el('strong', { text: 'Compilation failed: ' }),
        el('code', { class: 'text-danger', text: result.error || 'Unknown error' }),
      ]));
      return;
    }

    const ruleList = (result.rules || []).join(', ') || '—';
    container.appendChild(el('div', { class: 'alert alert-success small mb-2' }, [
      el('strong', { text: 'Compiles OK. ' }),
      el('span', { text: 'Rules: ' }),
      el('code', { text: ruleList }),
    ]));

    if (result.error) {
      container.appendChild(el('div', { class: 'alert alert-warning small mb-0', text: result.error }));
      return;
    }
    if (!result.tested) return;

    if (!result.matched) {
      container.appendChild(el('div', { class: 'alert alert-secondary small mb-0', text: 'No match for the sample text.' }));
      return;
    }

    const rows = (result.matches || []).map(function (m) {
      return el('tr', {}, [
        el('td', {}, [el('code', { text: m.rule })]),
        el('td', {}, [el('code', { text: m.identifier })]),
        el('td', {}, [el('mark', { text: m.data })]),
        el('td', { class: 'text-end', text: String(m.offset) }),
      ]);
    });
    const header = el('tr', {}, ['Rule', 'String', 'Matched text', 'Offset'].map(function (h, i) {
      return el('th', i === 3 ? { class: 'text-end', text: h } : { text: h });
    }));
    container.appendChild(el('div', { class: 'alert alert-info small mb-2' }, [
      el('strong', { text: 'Match! ' }),
      el('span', { text: result.matches.length + (result.truncated ? '+' : '') + ' string match(es) in the sample text.' }),
    ]));
    container.appendChild(el('div', { class: 'table-responsive' }, [
      el('table', { class: 'table table-sm small mb-0' }, [el('thead', {}, [header]), el('tbody', {}, rows)]),
    ]));
  }

  function renderLoading(container, label) {
    container.replaceChildren(el('div', { class: 'text-muted small' }, [
      el('span', { class: 'spinner-border spinner-border-sm me-2', role: 'status' }),
      el('span', { text: label || 'Compiling…' }),
    ]));
  }

  function renderRequestError(container, error) {
    container.replaceChildren(el('div', { class: 'alert alert-danger small mb-0', text: 'Request failed: ' + error.message }));
  }

  /* Compact badge for list rows. */
  function setBadge(badge, result) {
    badge.classList.remove('d-none', 'bg-success-subtle', 'text-success', 'bg-danger-subtle', 'text-danger', 'bg-secondary-subtle', 'text-secondary');
    if (result === 'loading') {
      badge.classList.add('bg-secondary-subtle', 'text-secondary');
      badge.textContent = '…';
      badge.removeAttribute('title');
      return;
    }
    if (result instanceof Error) {
      badge.classList.add('bg-secondary-subtle', 'text-secondary');
      badge.textContent = 'Error';
      badge.title = result.message;
      return;
    }
    if (result.ok) {
      badge.classList.add('bg-success-subtle', 'text-success');
      badge.textContent = 'Compiles';
      badge.title = 'Rules: ' + (result.rules || []).join(', ');
    } else {
      badge.classList.add('bg-danger-subtle', 'text-danger');
      badge.textContent = 'Invalid';
      badge.title = result.error || '';
    }
  }

  async function compileRow(button) {
    const row = button.closest('[data-rule-row]');
    const badge = row.querySelector('[data-compile-badge]');
    const errorBox = row.parentElement.querySelector('[data-compile-error-for="' + row.dataset.ruleId + '"]');
    button.disabled = true;
    setBadge(badge, 'loading');
    try {
      const result = await postForm(button.dataset.compileUrl, {});
      setBadge(badge, result);
      if (errorBox) {
        if (result.ok) {
          errorBox.classList.add('d-none');
        } else {
          errorBox.querySelector('code').textContent = result.error || '';
          errorBox.classList.remove('d-none');
        }
      }
      return result;
    } catch (error) {
      setBadge(badge, error);
      return { ok: false, error: error.message };
    } finally {
      button.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    // --- Rules list: per-row compile + compile all ---
    document.querySelectorAll('[data-compile-url][data-compile-row]').forEach(function (button) {
      button.addEventListener('click', function () { compileRow(button); });
    });

    const compileAll = document.querySelector('[data-compile-all]');
    if (compileAll) {
      compileAll.addEventListener('click', async function () {
        const buttons = Array.from(document.querySelectorAll('[data-compile-url][data-compile-row]'));
        const summary = document.querySelector('[data-compile-summary]');
        compileAll.disabled = true;
        const results = [];
        for (const button of buttons) results.push(await compileRow(button));
        compileAll.disabled = false;
        if (summary) {
          const invalid = results.filter(function (r) { return !r.ok; }).length;
          summary.classList.remove('d-none', 'alert-success', 'alert-danger');
          summary.classList.add(invalid ? 'alert-danger' : 'alert-success');
          summary.textContent = invalid
            ? invalid + ' of ' + results.length + ' rule(s) do not compile. Invalid rules are skipped when validating prompts.'
            : 'All ' + results.length + ' rule(s) compile correctly.';
        }
      });
    }

    // --- Detail page / form: compile + test panel ---
    document.querySelectorAll('[data-yara-tester]').forEach(function (panel) {
      const resultBox = panel.querySelector('[data-yara-result]');
      const sampleInput = panel.querySelector('[data-yara-sample]');
      const sourceSelector = panel.dataset.sourceInput;  // form: textarea with the rule being edited
      const url = panel.dataset.url;

      async function run(withSample) {
        const fields = {};
        if (sourceSelector) fields.yara_rule = document.querySelector(sourceSelector).value;
        if (withSample) {
          fields.test_text = sampleInput ? sampleInput.value : '';
          if (!fields.test_text) {
            resultBox.replaceChildren(el('div', { class: 'alert alert-warning small mb-0', text: 'Write a sample text to test the rule against.' }));
            return;
          }
        }
        renderLoading(resultBox, withSample ? 'Testing…' : 'Compiling…');
        try {
          renderResult(resultBox, await postForm(url, fields));
        } catch (error) {
          renderRequestError(resultBox, error);
        }
      }

      const compileBtn = panel.querySelector('[data-yara-compile]');
      const testBtn = panel.querySelector('[data-yara-test]');
      if (compileBtn) compileBtn.addEventListener('click', function () { run(false); });
      if (testBtn) testBtn.addEventListener('click', function () { run(true); });
    });
  });
})();
