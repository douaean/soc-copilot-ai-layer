import { useEffect, useMemo, useState } from 'react'
import './App.css'

const REVIEW_OPTIONS = ['ALL', 'pending', 'approved', 'rejected']
const RISK_OPTIONS = ['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

// Frontend-only demo alerts (sanitized). These are merged with backend alerts so the
// UI can display demo rows without modifying the backend DB. They contain no raw
// sensitive content (only sanitized/displayed text) and include a draft-rule entry
// for the sensitive demo alert.
const MOCK_FRONTEND_ALERTS = [
  {
    alert_id: 'fe_mock_sensitive_01',
    thread_id: null,
    timestamp: new Date().toISOString(),
    severity: 8,
    severity_label: 'HIGH',
    user_email: null,
    chat_name: 'demo',
    prompt: {
      displayed: '<PERSON> activity eintragen: genau <PERSON>, was <PERSON>',
      redacted: '<PERSON> activity eintragen: genau <PERSON>, was <PERSON>'
    },
    // Use PERSON placeholders (non-PII) so the UI treats this as a TP while keeping the
    // displayed text sanitized and safe for the dashboard.
    sensitive_entities: [
      { entity_type: 'PERSON', detector: 'mock', confidence: 0.95 },
      { entity_type: 'PERSON', detector: 'mock', confidence: 0.94 },
      { entity_type: 'PERSON', detector: 'mock', confidence: 0.93 }
    ],
    threat_intel: { investigation_summary: 'Sensitive-personal data exposure without matching coverage.', mitre_techniques: [], risk_score: 80, confidence: 0.9 },
    rule_status: { status: 'missing_coverage', rule_exists: false, generated_rule: '<rule id="demo-1"/>', generation_reason: 'No coverage', requires_rule_review: true },
    draft_rule: { rule_xml: '<rule id="demo-1"/>', approved: false, requires_human_review: true },
    analyst_result: { score: 90, confidence: 0.94, verdict: 'TRUE_POSITIVE' },
    investigation_summary: 'TRUE POSITIVE: sanitized sensitive request; draft rule generated for human review.',
    status: 'requires_review'
  },
  {
    alert_id: 'fe_mock_malicious_01',
    thread_id: null,
    timestamp: new Date().toISOString(),
    severity: 12,
    severity_label: 'CRITICAL',
    user_email: null,
    chat_name: 'demo',
    prompt: {
      displayed: 'A maintenance monitor detected behavior consistent with credential dumping and outbound data transfer.',
      redacted: 'A maintenance monitor detected behavior consistent with credential dumping and outbound data transfer.'
    },
    // Mark as TP for the frontend by including a non-PII indicator entity. This keeps the
    // mock sanitized while allowing the UI to classify it as a True Positive.
    sensitive_entities: [{ entity_type: 'MALICIOUS_INDICATOR', detector: 'mock', confidence: 0.98 }],
    threat_intel: { investigation_summary: 'Credential dumping and exfiltration pattern identified.', mitre_techniques: ['T1003', 'T1041'], risk_score: 96, confidence: 0.98 },
    rule_status: { status: 'clean', rule_exists: false },
    draft_rule: null,
    analyst_result: { score: 96, confidence: 0.98, verdict: 'TRUE_POSITIVE' },
    investigation_summary: 'TRUE POSITIVE: credential dumping and exfiltration behavior; escalate.',
    status: 'requires_review'
  }
]


function deriveReviewStatus(alert) {
  const status = (alert?.status || '').toLowerCase()
  if (status === 'resolved' || status === 'approved') return 'approved'
  if (status === 'rejected' || status === 'escalated') return 'rejected'
  if (status === 'requires_review' || status === 'new' || !status) return 'pending'
  return status
}

function isTP(alert) {
  return Array.isArray(alert?.sensitive_entities) && alert.sensitive_entities.length > 0
}

function riskDisplay(alert) {
  if (alert?.severity_label) return alert.severity_label
  if (alert?.threat_intel?.risk_score !== undefined) {
    if (alert.threat_intel.risk_score >= 85) return 'CRITICAL'
    if (alert.threat_intel.risk_score >= 70) return 'HIGH'
    if (alert.threat_intel.risk_score >= 40) return 'MEDIUM'
    return 'LOW'
  }
  return 'LOW'
}

function formatTimestamp(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  return d.toLocaleString()
}

function entityTypes(alert) {
  const entities = Array.isArray(alert?.sensitive_entities) ? alert.sensitive_entities : []
  return entities.map((entity) => entity?.entity_type || entity?.type || entity?.category || 'UNKNOWN')
}

function summaryText(alert) {
  if (alert?.analyst_result?.summary) return alert.analyst_result.summary
  if (alert?.threat_intel?.summary) return alert.threat_intel.summary
  if (alert?.investigation_summary) return alert.investigation_summary
  if (alert?.prompt?.displayed) return alert.prompt.displayed.slice(0, 180)
  return 'No investigation summary available.'
}

function App() {
  const [alerts, setAlerts] = useState([])
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [tpRiskFilter, setTpRiskFilter] = useState('ALL')
  const [reviewFilter, setReviewFilter] = useState('ALL')

  const loadAlerts = async () => {
    try {
      setLoading(true)
      const res = await fetch('/api/alerts?limit=100')
      if (!res.ok) throw new Error(`Request failed: ${res.status}`)
      const data = await res.json()
      const backendAlerts = Array.isArray(data) ? data : []
      // Merge frontend-only demo alerts without duplicating any backend rows
      const merged = [...backendAlerts]
      MOCK_FRONTEND_ALERTS.forEach((mock) => {
        if (!merged.find((a) => a.alert_id === mock.alert_id)) merged.push(mock)
      })
      setAlerts(merged)
      if (!selectedAlertId && merged[0]) {
        setSelectedAlertId(merged[0].alert_id)
      }
    } catch (err) {
      setError(err.message || 'Unable to load alerts')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAlerts()
  }, [])

  useEffect(() => {
    if (!selectedAlertId) return
    // Prefer the alert object from the local alerts array (includes frontend mocks)
    const local = alerts.find((a) => a.alert_id === selectedAlertId)
    if (local) {
      setSelectedAlert(local)
      return
    }

    let active = true
    fetch(`/api/alerts/${selectedAlertId}`)
      .then((res) => {
        if (!res.ok) throw new Error(`Detail fetch failed: ${res.status}`)
        return res.json()
      })
      .then((data) => {
        if (active) setSelectedAlert(data)
      })
      .catch((err) => {
        if (active) setError(err.message || 'Unable to load alert detail')
      })
    return () => {
      active = false
    }
  }, [selectedAlertId, alerts])

  const filteredAlerts = useMemo(() => {
    const term = search.trim().toLowerCase()
    return alerts.filter((alert) => {
      const kind = isTP(alert) ? 'TP' : 'FP'
      const matchesKind = true
      const matchesSearch = !term || [alert.alert_id, alert.chat_name, alert.user_email, alert.investigation_summary, alert.status].join(' ').toLowerCase().includes(term)
      const matchesReview = reviewFilter === 'ALL' || deriveReviewStatus(alert) === reviewFilter
      return matchesKind && matchesSearch && matchesReview
    })
  }, [alerts, search, reviewFilter])

  const tpAlerts = useMemo(() => {
    return filteredAlerts.filter((alert) => isTP(alert)).filter((alert) => {
      if (tpRiskFilter === 'ALL') return true
      return (riskDisplay(alert) || 'LOW').toUpperCase() === tpRiskFilter
    })
  }, [filteredAlerts, tpRiskFilter])

  const fpAlerts = useMemo(() => filteredAlerts.filter((alert) => !isTP(alert)), [filteredAlerts])

  const overallTotals = useMemo(() => {
    const total = alerts.length
    const tp = alerts.filter(isTP).length
    const fp = total - tp
    return { total, tp, fp }
  }, [alerts])

  const handleResume = async (decision) => {
    try {
      const body = {
        decision,
        reviewer: 'SOC analyst',
        comments: decision === 'APPROVED' ? 'Approved from dashboard' : 'Rejected from dashboard',
      }
      // Send thread_id when available; otherwise fall back to alert_id so the
      // backend can resolve the checkpoint. This handles older rows that
      // didn't persist the thread_id value.
      if (selectedAlert?.thread_id) {
        body.thread_id = selectedAlert.thread_id
      } else {
        body.alert_id = selectedAlert?.alert_id
      }

      const res = await fetch('/api/alerts/resume', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) throw new Error(`Resume failed: ${res.status}`)
      await loadAlerts()
      setSelectedAlertId(selectedAlert.alert_id)
    } catch (err) {
      setError(err.message || 'Unable to resume investigation')
    }
  }

  const handleDraftDecision = async (approved) => {
    if (!selectedAlert?.alert_id) return
    const ruleXml = selectedAlert?.draft_rule?.rule_xml || selectedAlert?.draft_rule?.xml || selectedAlert?.draft_rule?.generated_rule || selectedAlert?.rule_status?.generated_rule || '<rule id="manual-review" />'
    try {
      const res = await fetch(`/api/alerts/${selectedAlert.alert_id}/draft/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_xml: ruleXml, approved, approved_by: 'SOC analyst' }),
      })
      if (!res.ok) throw new Error(`Rule review failed: ${res.status}`)
      await loadAlerts()
      setSelectedAlertId(selectedAlert.alert_id)
    } catch (err) {
      setError(err.message || 'Unable to update draft rule')
    }
  }

  return (
    <div className="dashboard-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">AI SOC dashboard</p>
          <h1>Analyst triage queue</h1>
        </div>
        <button className="refresh-button" onClick={loadAlerts}>Refresh</button>
      </header>

      <section className="summary-row">
        <div className="summary-card">
          <span>Total alerts</span>
          <strong>{overallTotals.total}</strong>
        </div>
        <div className="summary-card tp-card">
          <span>True positives</span>
          <strong>{overallTotals.tp}</strong>
        </div>
        <div className="summary-card fp-card">
          <span>False positives</span>
          <strong>{overallTotals.fp}</strong>
        </div>
      </section>

      <section className="filters-bar">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search alert ID, chat, user, text..."
        />
        <select value={reviewFilter} onChange={(e) => setReviewFilter(e.target.value)}>
          {REVIEW_OPTIONS.map((option) => (
            <option key={option} value={option}>{option === 'ALL' ? 'All review states' : option}</option>
          ))}
        </select>
        <select value={tpRiskFilter} onChange={(e) => setTpRiskFilter(e.target.value)}>
          {RISK_OPTIONS.map((option) => (
            <option key={option} value={option}>{option === 'ALL' ? 'All TP risks' : option}</option>
          ))}
        </select>
      </section>

      {error && <div className="alert-banner error">{error}</div>}

      <main className="content-grid">
        <section className="board-column">
          <div className="queue-panel">
            <div className="panel-header">
              <h2>True Positive</h2>
              <span>{tpAlerts.length}</span>
            </div>
            {tpAlerts.length === 0 ? (
              <div className="empty-state">No TP alerts match the current filters.</div>
            ) : (
              tpAlerts.map((alert) => (
                <button
                  key={alert.alert_id}
                  className={`queue-item ${selectedAlertId === alert.alert_id ? 'active' : ''}`}
                  onClick={() => setSelectedAlertId(alert.alert_id)}
                >
                  <div className="row-head">
                    <span className="alert-id">{alert.alert_id}</span>
                    <span className="risk-pill risk-tp">{riskDisplay(alert)}</span>
                  </div>
                  <div className="meta-line">
                    <span>{formatTimestamp(alert.timestamp)}</span>
                    <span>{entityTypes(alert).length} entity types</span>
                  </div>
                  <div className="meta-line small">
                    <span>{deriveReviewStatus(alert)}</span>
                    <span>{alert.user_email || 'No user'}</span>
                  </div>
                  <div className="prompt-snippet">{(alert?.prompt?.displayed || '').slice(0,120)}</div>
                </button>
              ))
            )}
          </div>

          <div className="queue-panel">
            <div className="panel-header">
              <h2>False Positive</h2>
              <span>{fpAlerts.length}</span>
            </div>
            {fpAlerts.length === 0 ? (
              <div className="empty-state">No FP alerts match the current filters.</div>
            ) : (
              fpAlerts.map((alert) => (
                <button
                  key={alert.alert_id}
                  className={`queue-item ${selectedAlertId === alert.alert_id ? 'active' : ''}`}
                  onClick={() => setSelectedAlertId(alert.alert_id)}
                >
                  <div className="row-head">
                    <span className="alert-id">{alert.alert_id}</span>
                    <span className="risk-pill risk-fp">{summaryText(alert).slice(0, 18) || 'Investigation'}</span>
                  </div>
                  <div className="meta-line">
                    <span>{formatTimestamp(alert.timestamp)}</span>
                    <span>{alert.threat_intel?.mitre_techniques?.length || 0} MITRE techniques</span>
                  </div>
                  <div className="meta-line small">
                    <span>{deriveReviewStatus(alert)}</span>
                    <span>{alert.status || 'new'}</span>
                  </div>
                  <div className="prompt-snippet">{(alert?.prompt?.displayed || '').slice(0,120)}</div>
                </button>
              ))
            )}
          </div>
        </section>

        <aside className="detail-panel">
          {selectedAlert ? (
            <>
              <div className="detail-header">
                <div>
                  <p className="eyebrow">Alert detail</p>
                  <h2>{selectedAlert.alert_id}</h2>
                </div>
                <span className={`kind-badge ${isTP(selectedAlert) ? 'kind-tp' : 'kind-fp'}`}>
                  {isTP(selectedAlert) ? 'True Positive' : 'False Positive'}
                </span>
              </div>

              <div className="meta-block">
                <div><label>Timestamp</label><strong>{formatTimestamp(selectedAlert.timestamp)}</strong></div>
                <div><label>Risk</label><strong>{riskDisplay(selectedAlert)}</strong></div>
                <div><label>Review status</label><strong>{deriveReviewStatus(selectedAlert)}</strong></div>
                <div><label>User email</label><strong>{selectedAlert.user_email || '—'}</strong></div>
              </div>

              <div className="detail-section">
                <h3>Prompt (dashboard-safe)</h3>
                <pre>{selectedAlert.prompt?.displayed || '[UNAVAILABLE]'}</pre>
              </div>

              {isTP(selectedAlert) ? (
                <>
                  <div className="detail-section">
                    <h3>Detected entity types</h3>
                    <ul className="tag-list">
                      {entityTypes(selectedAlert).length ? entityTypes(selectedAlert).map((type) => <li key={type}>{type}</li>) : <li>None recorded</li>}
                    </ul>
                  </div>

                  <div className="detail-section">
                    <h3>True positive decision</h3>
                    <p>Analyst decision: accept this sensitive alert as a valid true positive, or refuse it if the detection should be overturned.</p>
                    <div className="action-row">
                      <button className="approve" onClick={() => handleResume('APPROVED')}>Accept TP</button>
                      <button className="reject" onClick={() => handleResume('REJECTED')}>Refuse TP</button>
                    </div>
                  </div>

                  <div className="detail-section">
                    <h3>Rule coverage</h3>
                    <pre>{JSON.stringify(selectedAlert.rule_status || selectedAlert.rule || {}, null, 2)}</pre>
                    {selectedAlert.draft_rule && (
                      <>
                        <h4>Draft rule XML</h4>
                        <pre>{typeof selectedAlert.draft_rule === 'string' ? selectedAlert.draft_rule : JSON.stringify(selectedAlert.draft_rule, null, 2)}</pre>
                        <div className="action-row">
                          <button className="approve" onClick={() => handleDraftDecision(true)}>Approve rule</button>
                          <button className="reject" onClick={() => handleDraftDecision(false)}>Reject rule</button>
                        </div>
                      </>
                    )}
                  </div>
                </>
              ) : (
                <>
                  <div className="detail-section">
                    <h3>Investigation summary</h3>
                    <p>{summaryText(selectedAlert)}</p>
                  </div>

                  <div className="detail-section">
                    <h3>MITRE techniques</h3>
                    <ul className="tag-list">
                      {(selectedAlert.threat_intel?.mitre_techniques || []).map((technique) => <li key={technique}>{technique}</li>)}
                    </ul>
                  </div>

                  <div className="detail-section">
                    <h3>Analyst verdict</h3>
                    {selectedAlert.analyst_result?.verdict === 'MALICIOUS' ? (
                      <div className="alert-banner">Malicious - requires immediate attention</div>
                    ) : null}
                    <pre>{JSON.stringify(selectedAlert.analyst_result || {}, null, 2)}</pre>
                  </div>

                  <div className="detail-section">
                    <h3>Human review</h3>
                    <div className="action-row">
                      <button className="approve" onClick={() => handleResume('APPROVED')}>Approve</button>
                      <button className="reject" onClick={() => handleResume('REJECTED')}>Reject</button>
                    </div>
                  </div>
                </>
              )}
            </>
          ) : (
            <div className="empty-state large">Select an alert to inspect the triage details.</div>
          )}
        </aside>
      </main>
    </div>
  )
}

export default App
