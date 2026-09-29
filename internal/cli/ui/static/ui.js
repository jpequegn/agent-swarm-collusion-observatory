'use strict';

const byId = (id) => document.getElementById(id);
let csrfToken = '';
let selectedRun = '';

function notice(message, isError = false) {
  const node = byId('notice');
  node.textContent = message;
  node.classList.toggle('error', isError);
  node.hidden = false;
}

function clearNotice() {
  byId('notice').hidden = true;
}

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', ...options });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed (${response.status})`);
  }
  return payload;
}

function postJSON(path, body) {
  return api(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify(body),
  });
}

function textNode(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value == null || value === '' ? '—' : String(value);
  if (className) node.className = className;
  return node;
}

function setButtons(enabled) {
  for (const id of ['verify-run', 'evaluate-run', 'replay-run', 'show-truth']) {
    byId(id).disabled = !enabled;
  }
}

function addBadge(label, className = '') {
  const badge = textNode('span', label, `badge ${className}`.trim());
  byId('run-badges').append(badge);
}

function setRun(detail) {
  selectedRun = detail.run_id;
  byId('run-id-input').value = detail.run_id;
  byId('run-title').textContent = detail.run_id;
  byId('run-badges').replaceChildren();
  addBadge(detail.scenario_id);
  addBadge(detail.topology);
  addBadge(detail.completed ? 'COMPLETE' : 'INCOMPLETE', detail.completed ? 'good' : 'warn');
  addBadge(detail.integrity_verified ? 'INTEGRITY VERIFIED' : 'UNVERIFIED', detail.integrity_verified ? 'good' : 'bad');
  byId('public-count').textContent = detail.truncated ? `${detail.public_events.length} / ${detail.public_total}` : String(detail.public_total);
  byId('monitor-count').textContent = detail.truncated ? `${detail.monitor_records.length} / ${detail.monitor_total}` : String(detail.monitor_total);
  renderPublicEvents(detail.public_events);
  renderMonitorEvents(detail.monitor_records);
  byId('integrity-details').replaceChildren(
    keyValue('Status', detail.integrity_verified ? 'Verified' : 'Unverified'),
    keyValue('Completion', detail.completed ? 'Complete' : 'Incomplete'),
    keyValue('Public records', detail.public_total),
    keyValue('Monitor records', detail.monitor_total),
  );
  byId('evaluation-details').textContent = 'Run evaluation when ready.';
  byId('replay-details').textContent = 'Replay this verified decision trace.';
  byId('truth-details').textContent = 'Hidden until explicitly requested for a complete verified run.';
  setButtons(detail.completed && detail.integrity_verified);
}

function keyValue(label, value) {
  const row = document.createElement('div');
  row.append(textNode('dt', label), textNode('dd', value));
  return row;
}

function renderPublicEvents(events) {
  const list = byId('public-events');
  list.replaceChildren();
  list.classList.toggle('empty-state', events.length === 0);
  if (!events.length) {
    list.append(textNode('li', 'No public events recorded.'));
    return;
  }
  for (const event of events) {
    const row = document.createElement('li');
    row.className = 'event-row';
    row.append(textNode('span', `T${event.tick}`, 'event-tick'));
    const main = document.createElement('div');
    main.className = 'event-main';
    const title = document.createElement('div');
    title.className = 'event-title';
    title.append(textNode('span', event.kind));
    if (event.outcome) title.append(textNode('span', event.outcome, `event-tag ${event.outcome}`));
    if (event.actor_id) title.append(textNode('span', event.actor_id, 'event-tag'));
    const detail = [event.intent_kind, event.path, event.reason_code, event.artifact_id, event.recipient]
      .filter(Boolean).join(' · ');
    main.append(title);
    if (detail) main.append(textNode('div', detail, 'event-meta'));
    row.append(main);
    list.append(row);
  }
}

function renderMonitorEvents(records) {
  const list = byId('monitor-events');
  list.replaceChildren();
  list.classList.toggle('empty-state', records.length === 0);
  if (!records.length) {
    list.append(textNode('li', 'No monitor decisions recorded.'));
    return;
  }
  for (const record of records) {
    const row = document.createElement('li');
    row.className = 'event-row';
    row.append(textNode('span', `T${record.tick}`, 'event-tick'));
    const main = document.createElement('div');
    main.className = 'event-main';
    const title = document.createElement('div');
    title.className = 'event-title';
    title.append(textNode('span', `monitor ${record.kind}`));
    if (record.outcome) title.append(textNode('span', record.outcome, `event-tag ${record.outcome}`));
    const actor = record.observation && record.observation.actor_id;
    if (actor) title.append(textNode('span', actor, 'event-tag'));
    let detail = record.rule_id || '';
    if (record.action) {
      const action = record.action;
      detail = [action.kind, action.actor_id, action.capability, action.artifact_id].filter(Boolean).join(' · ');
    } else if (record.observation) {
      detail = [record.observation.event_kind, record.observation.outcome, record.observation.reason_code].filter(Boolean).join(' · ');
    }
    main.append(title);
    if (detail) main.append(textNode('div', detail, 'event-meta'));
    row.append(main);
    list.append(row);
  }
}

function renderEvaluation(report) {
  const metrics = report.metrics;
  const details = document.createElement('dl');
  details.className = 'metric-list';
  const values = [
    ['Mergeable', metrics.task_quality.mergeable ? 'Yes' : 'No'],
    ['Latest verifier', metrics.task_quality.latest_verification_ok ? 'Passed' : 'Not passed'],
    ['Evidence coverage', `${metrics.verification.evidence_coverage_rate}`],
    ['Duplicate actions', metrics.actions.duplicate_actions],
    ['Detection', metrics.monitor.detection.detected ? 'Detected' : 'Not detected'],
    ['False positive', metrics.monitor.false_positive_run ? 'Yes' : 'No'],
    ['Safe bailouts', metrics.abstention.safe_bailouts],
    ['Replay compared', metrics.replay.compared ? (metrics.replay.faithful ? 'Faithful' : 'Mismatch') : 'No'],
  ];
  for (const [label, value] of values) details.append(keyValue(label, value));
  byId('evaluation-details').replaceChildren(details);
}

function runPath(suffix = '') {
  return `/api/runs/${encodeURIComponent(selectedRun)}${suffix}`;
}

async function initialize() {
  try {
    const session = await api('/api/session');
    csrfToken = session.csrf_token;
    const catalog = await api('/api/fixtures');
    const select = byId('fixture');
    for (const fixture of catalog.fixtures) {
      const option = document.createElement('option');
      option.value = fixture.id;
      option.textContent = `${fixture.id} - ${fixture.description}`;
      select.append(option);
    }
    setButtons(false);
  } catch (error) {
    notice(error.message, true);
  }
}

byId('start-run').addEventListener('click', async () => {
  clearNotice();
  byId('start-run').disabled = true;
  try {
    const topology = document.querySelector('input[name="topology"]:checked').value;
    const detail = await postJSON('/api/runs', {
      fixture: byId('fixture').value,
      topology,
      worker_policy: byId('worker-policy').value,
    });
    setRun(detail);
    notice('Run completed and its evidence seal verified.');
  } catch (error) {
    notice(error.message, true);
  } finally {
    byId('start-run').disabled = false;
  }
});

byId('open-run').addEventListener('click', async () => {
  clearNotice();
  const value = byId('run-id-input').value.trim();
  if (!value) return notice('Enter a run ID.', true);
  try {
    setRun(await api(`/api/runs/${encodeURIComponent(value)}`));
  } catch (error) {
    notice(error.message, true);
  }
});

byId('verify-run').addEventListener('click', async () => {
  clearNotice();
  try {
    const result = await api(runPath('/verify'));
    byId('integrity-details').replaceChildren(
      keyValue('Status', result.verified ? 'Verified' : 'Failed'),
      keyValue('Completion', result.completed ? 'Complete' : 'Incomplete'),
      keyValue('Public records', result.public_count),
      keyValue('Decisions', result.decision_count),
      keyValue('Monitor records', result.monitor_count),
    );
    notice('Integrity verification passed.');
  } catch (error) {
    notice(error.message, true);
  }
});

byId('evaluate-run').addEventListener('click', async () => {
  clearNotice();
  try {
    renderEvaluation(await api(runPath('/evaluation')));
  } catch (error) {
    notice(error.message, true);
  }
});

byId('show-truth').addEventListener('click', async () => {
  clearNotice();
  try {
    const projection = await api(runPath('/truth'));
    const block = textNode('pre', JSON.stringify(projection.truth_records, null, 2), 'json-block');
    byId('truth-details').replaceChildren(block);
  } catch (error) {
    notice(error.message, true);
  }
});

byId('replay-run').addEventListener('click', async () => {
  clearNotice();
  byId('replay-run').disabled = true;
  try {
    const response = await postJSON(runPath('/replay'), {});
    const sourceRun = selectedRun;
    setRun(response.replay);
    byId('replay-details').replaceChildren(
      keyValue('Faithful', response.faithful ? 'Yes' : 'No'),
      keyValue('Source run', sourceRun),
      keyValue('Replay run', response.replay.run_id),
    );
    notice('Replay completed with matching semantic evidence.');
  } catch (error) {
    notice(error.message, true);
  } finally {
    byId('replay-run').disabled = false;
  }
});

initialize();
