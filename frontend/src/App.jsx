import React, { useState, useEffect, useCallback, useRef } from 'react'
/* Sentry UI v2 */

const API = '/api'

/* ══════════════════════════════════════════════════════════
   DATA HOOK
   ══════════════════════════════════════════════════════════ */
function useApi(endpoint, interval = null) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const fetchData = useCallback(async () => {
    try {
      const res = await fetch(`${API}${endpoint}`)
      if (!res.ok) throw new Error(`${res.status}`)
      setData(await res.json())
      setError(null)
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }, [endpoint])
  useEffect(() => {
    fetchData()
    if (interval) { const id = setInterval(fetchData, interval); return () => clearInterval(id) }
  }, [fetchData, interval])
  return { data, error, loading, refresh: fetchData }
}

/* ══════════════════════════════════════════════════════════
   DESIGN TOKENS
   ══════════════════════════════════════════════════════════ */
const c = {
  bg: '#0b0d13', surface: '#141721', surfaceAlt: '#1a1e2e',
  border: '#232840', borderLight: '#2e3452',
  text: '#e4e8f1', textDim: '#8891a8', textFaint: '#5c637a',
  accent: '#7c6aef', accentDim: '#6c5ce722',
  green: '#34d399', greenDim: '#34d39920',
  red: '#f87171', redDim: '#f8717120',
  orange: '#fbbf24', orangeDim: '#fbbf2420',
  cyan: '#22d3ee', cyanDim: '#22d3ee20',
  pink: '#f472b6', pinkDim: '#f472b620',
}

const PHASE_META = {
  triage:       { icon: '🔍', label: 'Triage',       color: c.orange, effort: 'Low' },
  diagnosis:    { icon: '🧠', label: 'Diagnosis',    color: c.cyan,   effort: 'High' },
  remediation:  { icon: '🔧', label: 'Remediation',  color: c.accent, effort: 'Medium' },
  verification: { icon: '✅', label: 'Verification', color: c.green,  effort: 'Disabled' },
}

const ACTIVITY_ICONS = {
  phase_start:    '▶',
  phase_complete: '✓',
  llm_call:       '🤖',
  tool_call:      '⚙',
  tool_result:    '📋',
  decision:       '💡',
  error:          '❌',
  info:           'ℹ',
}

/* ══════════════════════════════════════════════════════════
   GLOBAL STYLES (injected once)
   ══════════════════════════════════════════════════════════ */
function GlobalStyles() {
  return <style>{`
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { margin: 0; background: ${c.bg}; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
    ::-webkit-scrollbar { width: 5px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: ${c.border}; border-radius: 3px; }
    input:focus { border-color: ${c.accent} !important; outline: none; }
    button { cursor: pointer; border: none; font-family: inherit; }
    button:hover { opacity: 0.92; }
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
    @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
    @keyframes slideDown { from { opacity: 0; max-height: 0; } to { opacity: 1; max-height: 2000px; } }
    @keyframes spin { to { transform: rotate(360deg); } }
    .fade-in { animation: fadeIn 0.35s ease-out; }
    .pulse { animation: pulse 1.8s ease-in-out infinite; }
  `}</style>
}

/* ══════════════════════════════════════════════════════════
   TINY COMPONENTS
   ══════════════════════════════════════════════════════════ */
function Badge({ color, children, small }) {
  return <span style={{
    display: 'inline-flex', alignItems: 'center', gap: '4px',
    padding: small ? '2px 8px' : '4px 12px', borderRadius: '6px',
    fontSize: small ? '10px' : '11px', fontWeight: 600, letterSpacing: '0.3px',
    background: `${color}18`, color, border: `1px solid ${color}30`,
    whiteSpace: 'nowrap',
  }}>{children}</span>
}

function Spinner({ size = 14 }) {
  return <span style={{
    display: 'inline-block', width: size, height: size, borderRadius: '50%',
    border: `2px solid ${c.border}`, borderTopColor: c.accent,
    animation: 'spin 0.8s linear infinite',
  }} />
}

function Card({ children, style, className }) {
  return <div className={className} style={{
    background: c.surface, borderRadius: '14px',
    border: `1px solid ${c.border}`, padding: '20px',
    transition: 'border-color 0.25s, box-shadow 0.25s', ...style,
  }}>{children}</div>
}

function SectionTitle({ icon, children, right }) {
  return <div style={{
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    marginBottom: '16px',
  }}>
    <div style={{
      fontSize: '12px', fontWeight: 700, textTransform: 'uppercase',
      letterSpacing: '0.8px', color: c.textDim,
      display: 'flex', alignItems: 'center', gap: '8px',
    }}>{icon && <span style={{ fontSize: '14px' }}>{icon}</span>}{children}</div>
    {right}
  </div>
}

/* ══════════════════════════════════════════════════════════
   HEADER
   ══════════════════════════════════════════════════════════ */
function Header({ status, onRefresh }) {
  return <header style={{
    background: c.surface, borderBottom: `1px solid ${c.border}`,
    padding: '14px 28px', display: 'flex', alignItems: 'center',
    justifyContent: 'space-between', position: 'sticky', top: 0, zIndex: 100,
  }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
      <span style={{ fontSize: '26px' }}>🛡️</span>
      <div>
        <div style={{ fontSize: '18px', fontWeight: 800, color: c.text, letterSpacing: '-0.5px' }}>
          Sentry
        </div>
        <div style={{ fontSize: '11px', color: c.textFaint, fontWeight: 500 }}>
          Self-Healing Server Monitor
        </div>
      </div>
    </div>
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
      {status && <Badge color={status.mode === 'ACTIVE' ? c.green : status.mode === 'AUDIT' ? c.orange : c.red}>
        {status.mode}
      </Badge>}
      <button onClick={onRefresh} style={{
        padding: '7px 16px', borderRadius: '8px', fontSize: '12px', fontWeight: 600,
        background: c.surfaceAlt, color: c.textDim, border: `1px solid ${c.border}`,
      }}>↻ Refresh</button>
    </div>
  </header>
}

/* ══════════════════════════════════════════════════════════
   STATUS ROW — compact overview metrics
   ══════════════════════════════════════════════════════════ */
function StatusRow({ status }) {
  if (!status) return null
  const cb = status.circuit_breaker || {}
  const pct = cb.max_cost_usd > 0 ? Math.min(100, (cb.current_cost_usd / cb.max_cost_usd) * 100) : 0

  return <div style={{
    display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px', marginBottom: '20px',
  }}>
    {[
      { label: 'Active Incidents', value: status.active_incidents || 0, color: status.active_incidents > 0 ? c.orange : c.green },
      { label: 'Resolved Total', value: status.resolved_total || 0, color: c.cyan },
      { label: 'API Cost', value: `$${(cb.current_cost_usd || 0).toFixed(4)}`, color: pct > 80 ? c.red : pct > 50 ? c.orange : c.green },
      { label: 'Circuit Breaker', value: cb.tripped ? 'TRIPPED' : 'OK', color: cb.tripped ? c.red : c.green },
    ].map((m, i) => (
      <Card key={i} style={{ padding: '16px 18px' }}>
        <div style={{ fontSize: '11px', fontWeight: 600, color: c.textDim, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
          {m.label}
        </div>
        <div style={{ fontSize: '28px', fontWeight: 800, color: m.color, lineHeight: 1.1 }}>
          {m.value}
        </div>
      </Card>
    ))}
  </div>
}

/* ══════════════════════════════════════════════════════════
   WATCHER CONTROL
   ══════════════════════════════════════════════════════════ */
function WatcherControl({ running, onToggle }) {
  const handleToggle = async () => {
    const endpoint = running ? '/api/watcher/stop' : '/api/watcher/start'
    try { await fetch(endpoint, { method: 'POST' }); onToggle() } catch (e) { console.error(e) }
  }
  return <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
    <span style={{
      width: 8, height: 8, borderRadius: '50%',
      background: running ? c.green : c.red,
      boxShadow: running ? `0 0 8px ${c.green}` : 'none',
    }} />
    <span style={{ fontSize: '12px', color: c.textDim }}>{running ? 'Watching' : 'Stopped'}</span>
    <button onClick={handleToggle} style={{
      padding: '5px 14px', borderRadius: '7px', fontSize: '11px', fontWeight: 600,
      background: running ? c.redDim : c.greenDim,
      color: running ? c.red : c.green,
      border: `1px solid ${running ? c.red + '40' : c.green + '40'}`,
    }}>{running ? '⏹ Stop' : '▶ Start'}</button>
  </div>
}

/* ══════════════════════════════════════════════════════════
   TRIGGER PANEL
   ══════════════════════════════════════════════════════════ */
function TriggerPanel({ onTrigger }) {
  const [msg, setMsg] = useState('')
  const [sending, setSending] = useState(false)
  const [lastResult, setLastResult] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!msg.trim()) return
    setSending(true); setLastResult(null)
    try {
      const res = await fetch(`${API}/trigger`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg, source: 'dashboard' }),
      })
      const data = await res.json()
      setLastResult(data)
      setMsg('')
      if (onTrigger) onTrigger()
    } catch (e) { setLastResult({ error: e.message }) }
    finally { setSending(false) }
  }

  return <Card style={{ marginBottom: '20px' }}>
    <SectionTitle icon="🚨">Manual Trigger</SectionTitle>
    <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '10px' }}>
      <input value={msg} onChange={e => setMsg(e.target.value)}
        placeholder='Paste an error: "ConnectionRefusedError: [Errno 111] Connection refused"'
        style={{
          flex: 1, padding: '10px 14px', borderRadius: '9px',
          border: `1px solid ${c.border}`, background: c.bg,
          color: c.text, fontSize: '13px', fontFamily: "'JetBrains Mono', monospace",
        }} />
      <button type="submit" disabled={sending} style={{
        padding: '10px 22px', borderRadius: '9px', fontWeight: 700, fontSize: '13px',
        background: c.accent, color: '#fff',
        opacity: sending ? 0.6 : 1,
      }}>{sending ? <><Spinner size={12} /> Processing...</> : '🔥 Trigger'}</button>
    </form>
    {lastResult && (
      <div className="fade-in" style={{
        marginTop: '10px', padding: '10px 14px', borderRadius: '8px',
        background: c.bg, fontSize: '12px', fontFamily: "'JetBrains Mono', monospace",
        color: c.textDim, maxHeight: '100px', overflowY: 'auto',
        border: `1px solid ${c.border}`,
      }}>
        {lastResult.incident
          ? `✓ Incident created: ${lastResult.incident.id} — ${lastResult.incident.state}`
          : lastResult.error || 'No incident created'}
      </div>
    )}
  </Card>
}

/* ══════════════════════════════════════════════════════════
   PHASE STEPPER — horizontal progress for an incident
   ══════════════════════════════════════════════════════════ */
function PhaseStepper({ phaseSummary, currentAction }) {
  const phases = ['triage', 'diagnosis', 'remediation', 'verification']

  return <div style={{ marginBottom: '16px' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
      {phases.map((phase, idx) => {
        const status = phaseSummary?.[phase] || 'pending'
        const meta = PHASE_META[phase]
        const isComplete = status === 'complete'
        const isActive = status === 'active'
        const isPending = status === 'pending'

        return <React.Fragment key={phase}>
          {/* Phase node */}
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            flex: 1, position: 'relative',
          }}>
            <div style={{
              width: 36, height: 36, borderRadius: '50%',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: isActive ? '16px' : '14px',
              background: isComplete ? `${meta.color}25` : isActive ? `${meta.color}15` : c.surfaceAlt,
              border: `2px solid ${isComplete ? meta.color : isActive ? meta.color : c.border}`,
              boxShadow: isActive ? `0 0 12px ${meta.color}30` : 'none',
              transition: 'all 0.4s',
              position: 'relative',
            }}>
              {isActive && <div className="pulse" style={{
                position: 'absolute', inset: -4, borderRadius: '50%',
                border: `2px solid ${meta.color}40`,
              }} />}
              {isComplete ? <span style={{ color: meta.color }}>✓</span> : meta.icon}
            </div>
            <div style={{
              marginTop: '6px', fontSize: '10px', fontWeight: 700,
              textTransform: 'uppercase', letterSpacing: '0.5px',
              color: isActive ? meta.color : isComplete ? c.textDim : c.textFaint,
            }}>{meta.label}</div>
            {isActive && (
              <div style={{
                fontSize: '9px', color: meta.color, marginTop: '2px', opacity: 0.8,
                fontWeight: 500,
              }}>effort: {meta.effort}</div>
            )}
          </div>
          {/* Connector line */}
          {idx < phases.length - 1 && (
            <div style={{
              flex: '0.5', height: '2px', marginTop: '-20px',
              background: isComplete ? meta.color : c.border,
              borderRadius: '1px', transition: 'background 0.4s',
            }} />
          )}
        </React.Fragment>
      })}
    </div>
    {/* Current agent action */}
    {currentAction && (
      <div className="fade-in" style={{
        marginTop: '12px', padding: '8px 14px', borderRadius: '8px',
        background: `${c.accent}10`, border: `1px solid ${c.accent}25`,
        display: 'flex', alignItems: 'center', gap: '8px',
        fontSize: '12px', color: c.accent, fontWeight: 500,
      }}>
        <Spinner size={12} />
        {currentAction}
      </div>
    )}
  </div>
}

/* ══════════════════════════════════════════════════════════
   ACTIVITY FEED — per-incident log of agent actions
   ══════════════════════════════════════════════════════════ */
function ActivityFeed({ activities, maxItems = 15 }) {
  const [expanded, setExpanded] = useState(false)
  if (!activities || activities.length === 0) return null

  const displayItems = expanded ? activities : activities.slice(-maxItems)
  const hasMore = activities.length > maxItems && !expanded

  return <div>
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      marginBottom: '8px',
    }}>
      <div style={{
        fontSize: '11px', fontWeight: 700, color: c.textDim,
        textTransform: 'uppercase', letterSpacing: '0.5px',
      }}>Agent Activity ({activities.length})</div>
      {hasMore && (
        <button onClick={() => setExpanded(true)} style={{
          fontSize: '10px', color: c.accent, background: 'none', fontWeight: 600,
        }}>Show all ↓</button>
      )}
    </div>
    <div style={{
      maxHeight: expanded ? '600px' : '360px', overflowY: 'auto',
      paddingRight: '4px',
    }}>
      {displayItems.map((act, i) => (
        <ActivityItem key={i} act={act} isLast={i === displayItems.length - 1} />
      ))}
    </div>
  </div>
}

function ActivityItem({ act, isLast }) {
  const [detailOpen, setDetailOpen] = useState(false)
  const icon = ACTIVITY_ICONS[act.activity_type] || '•'
  const isToolCall = act.activity_type === 'tool_call'
  const isToolResult = act.activity_type === 'tool_result'
  const isLLM = act.activity_type === 'llm_call'
  const isDecision = act.activity_type === 'decision'
  const isError = act.activity_type === 'error'
  const isPhaseStart = act.activity_type === 'phase_start'
  const isPhaseComplete = act.activity_type === 'phase_complete'

  const phaseColor = PHASE_META[act.phase]?.color || c.textDim
  const hasDetail = act.detail && act.detail.length > 0

  // Choose row color
  let rowBg = 'transparent'
  let rowBorder = 'transparent'
  if (isDecision) { rowBg = `${c.accent}08`; rowBorder = `${c.accent}20` }
  else if (isError) { rowBg = `${c.red}08`; rowBorder = `${c.red}20` }
  else if (isPhaseStart) { rowBg = `${phaseColor}06`; rowBorder = `${phaseColor}15` }

  const time = new Date(act.timestamp).toLocaleTimeString('en-US', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  })

  return <div style={{
    display: 'flex', gap: '10px', padding: '7px 10px',
    borderLeft: `2px solid ${isPhaseComplete ? phaseColor : isError ? c.red : c.border}`,
    marginBottom: isLast ? 0 : '1px',
    background: rowBg, borderRadius: '0 6px 6px 0',
    transition: 'background 0.2s',
  }}>
    {/* Timeline dot and icon */}
    <div style={{
      width: '22px', textAlign: 'center', fontSize: '12px',
      flexShrink: 0, paddingTop: '1px',
    }}>{icon}</div>

    {/* Content */}
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
        <span style={{
          fontSize: '12px', fontWeight: isDecision || isPhaseStart ? 600 : 500,
          color: isError ? c.red : isDecision ? c.text : c.textDim,
        }}>{act.title}</span>

        {/* Phase badge */}
        <Badge color={phaseColor} small>{act.phase}</Badge>

        {/* Tool badge */}
        {(isToolCall || isToolResult) && act.metadata?.tool && (
          <Badge color={isToolResult ? (act.metadata.success ? c.green : c.red) : c.cyan} small>
            {act.metadata.tool}
          </Badge>
        )}

        {/* LLM effort badge */}
        {isLLM && act.metadata?.effort && (
          <Badge color={c.pink} small>effort: {act.metadata.effort}</Badge>
        )}

        {/* Token counts */}
        {act.metadata?.input_tokens > 0 && (
          <span style={{ fontSize: '10px', color: c.textFaint }}>
            {act.metadata.input_tokens}↓ {act.metadata.output_tokens}↑ tokens
          </span>
        )}

        {/* Timestamp */}
        <span style={{ fontSize: '10px', color: c.textFaint, marginLeft: 'auto', flexShrink: 0 }}>
          {time}
        </span>
      </div>

      {/* Expandable detail */}
      {hasDetail && (
        <div style={{ marginTop: '3px' }}>
          <button onClick={() => setDetailOpen(!detailOpen)} style={{
            fontSize: '10px', color: c.accent, background: 'none',
            fontWeight: 500, padding: 0,
          }}>{detailOpen ? '▾ Hide detail' : '▸ Show detail'}</button>
          {detailOpen && (
            <div className="fade-in" style={{
              marginTop: '4px', padding: '8px 10px', borderRadius: '6px',
              background: c.bg, fontSize: '11px', lineHeight: 1.6,
              color: c.textDim, fontFamily: "'JetBrains Mono', monospace",
              wordBreak: 'break-word', border: `1px solid ${c.border}`,
              maxHeight: '200px', overflowY: 'auto',
            }}>{act.detail}</div>
          )}
        </div>
      )}
    </div>
  </div>
}

/* ══════════════════════════════════════════════════════════
   INCIDENT CARD — main expandable card per incident
   ══════════════════════════════════════════════════════════ */
function IncidentCard({ inc }) {
  const [expanded, setExpanded] = useState(false)
  const isActive = !['resolved', 'escalated', 'idle'].includes(inc.state)

  const severityColor =
    inc.severity === 'critical' ? c.red :
    inc.severity === 'high' ? c.orange :
    inc.severity === 'medium' ? c.cyan : c.textDim

  const stateColor =
    inc.state === 'resolved' ? c.green :
    inc.state === 'escalated' ? c.red :
    inc.state === 'idle' ? c.textFaint : c.orange

  // Count tool calls in activity log
  const toolCalls = (inc.activity_log || []).filter(a => a.activity_type === 'tool_call')
  const llmCalls = (inc.activity_log || []).filter(a => a.activity_type === 'llm_call')
  const decisions = (inc.activity_log || []).filter(a => a.activity_type === 'decision')

  return <Card className="fade-in" style={{
    marginBottom: '10px',
    borderColor: expanded ? `${c.accent}50` : isActive ? `${stateColor}30` : c.border,
    boxShadow: isActive ? `0 0 20px ${stateColor}08` : 'none',
  }}>
    {/* ── Header Row ── */}
    <div onClick={() => setExpanded(!expanded)} style={{
      display: 'flex', alignItems: 'center', gap: '14px',
      cursor: 'pointer', userSelect: 'none',
    }}>
      {/* State icon with pulse */}
      <div style={{ position: 'relative', flexShrink: 0 }}>
        <div style={{
          width: 40, height: 40, borderRadius: '10px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `${stateColor}15`, fontSize: '18px',
        }}>
          {inc.state === 'resolved' ? '🎉' :
           inc.state === 'escalated' ? '🚨' :
           inc.state === 'triage' ? '🔍' :
           inc.state === 'diagnosis' ? '🧠' :
           inc.state === 'remediation' ? '🔧' :
           inc.state === 'verification' ? '✅' : '⏸'}
        </div>
        {isActive && <div className="pulse" style={{
          position: 'absolute', top: -2, right: -2, width: 10, height: 10,
          borderRadius: '50%', background: stateColor,
          border: `2px solid ${c.surface}`,
        }} />}
      </div>

      {/* Symptom and metadata */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: '10px',
            color: c.textFaint, fontWeight: 500,
          }}>{inc.id}</span>
          <Badge color={stateColor}>{inc.state.toUpperCase()}</Badge>
          <Badge color={severityColor} small>{(inc.severity || 'unknown').toUpperCase()}</Badge>
        </div>
        <div style={{
          fontSize: '13px', fontWeight: 500, color: c.text, lineHeight: 1.4,
          overflow: 'hidden', textOverflow: 'ellipsis',
          display: '-webkit-box', WebkitLineClamp: expanded ? 'unset' : 2,
          WebkitBoxOrient: 'vertical',
        }}>
          {inc.triage_result || inc.symptom}
        </div>
      </div>

      {/* Quick stats pills */}
      <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexShrink: 0 }}>
        {toolCalls.length > 0 && (
          <span style={{
            fontSize: '10px', color: c.cyan, background: c.cyanDim,
            padding: '3px 8px', borderRadius: '12px', fontWeight: 600,
          }}>⚙ {toolCalls.length} tools</span>
        )}
        {llmCalls.length > 0 && (
          <span style={{
            fontSize: '10px', color: c.pink, background: c.pinkDim,
            padding: '3px 8px', borderRadius: '12px', fontWeight: 600,
          }}>🤖 {llmCalls.length} calls</span>
        )}
        <span style={{
          fontSize: '10px', color: c.textFaint,
          padding: '3px 8px', borderRadius: '12px', fontWeight: 500,
          background: c.surfaceAlt,
        }}>${(inc.cost_usd || 0).toFixed(4)}</span>
        <span style={{
          fontSize: '16px', color: c.textFaint, transition: 'transform 0.25s',
          transform: expanded ? 'rotate(180deg)' : 'rotate(0)',
        }}>▾</span>
      </div>
    </div>

    {/* ── Live Action Banner (when active) ── */}
    {isActive && inc.current_agent_action && !expanded && (
      <div className="fade-in" style={{
        marginTop: '10px', padding: '7px 12px', borderRadius: '8px',
        background: `${c.accent}08`, border: `1px solid ${c.accent}18`,
        display: 'flex', alignItems: 'center', gap: '8px',
        fontSize: '11px', color: c.accent, fontWeight: 500,
      }}>
        <Spinner size={11} />
        {inc.current_agent_action}
      </div>
    )}

    {/* ── Expanded Content ── */}
    {expanded && (
      <div className="fade-in" style={{
        marginTop: '16px', paddingTop: '16px',
        borderTop: `1px solid ${c.border}`,
      }}>
        {/* Phase Stepper */}
        <PhaseStepper phaseSummary={inc.phase_summary} currentAction={inc.current_agent_action} />

        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '16px',
        }}>
          {/* Left: Key info cards */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, color: c.textDim, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
              Resolution Details
            </div>
            {inc.triage_result && (
              <InfoBlock icon="🔍" title="Triage Result" color={c.orange}>
                {inc.triage_result}
              </InfoBlock>
            )}
            {inc.root_cause && (
              <InfoBlock icon="🎯" title="Root Cause" color={c.cyan}>
                {inc.root_cause}
              </InfoBlock>
            )}
            {inc.fix_applied && (
              <InfoBlock icon="🔧" title="Fix Applied" color={c.green}>
                {inc.fix_applied}
              </InfoBlock>
            )}
            {inc.commit_id && (
              <InfoBlock icon="📝" title="Git Commit" color={c.accent}>
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '13px', fontWeight: 700, color: c.accent,
                  background: `${c.accent}15`, padding: '3px 10px',
                  borderRadius: '6px', border: `1px solid ${c.accent}30`,
                  display: 'inline-block',
                }}>{inc.commit_id}</span>
              </InfoBlock>
            )}
            <InfoBlock icon="📊" title="Metrics" color={c.textDim}>
              <span>Retries: {inc.retry_count || 0} • Cost: ${(inc.cost_usd || 0).toFixed(4)} • Activities: {(inc.activity_log || []).length}</span>
            </InfoBlock>
            {inc.created_at && (
              <InfoBlock icon="🕐" title="Timeline" color={c.textDim}>
                <div>Created: {new Date(inc.created_at).toLocaleString()}</div>
                {inc.resolved_at && <div>Resolved: {new Date(inc.resolved_at).toLocaleString()}</div>}
                {inc.resolved_at && inc.created_at && (
                  <div style={{ color: c.green, fontWeight: 600, marginTop: '2px' }}>
                    Duration: {formatDuration(new Date(inc.created_at), new Date(inc.resolved_at))}
                  </div>
                )}
              </InfoBlock>
            )}
          </div>

          {/* Right: Activity Feed */}
          <div>
            <ActivityFeed activities={inc.activity_log || []} />
          </div>
        </div>
      </div>
    )}
  </Card>
}

function InfoBlock({ icon, title, color, children }) {
  return <div style={{
    padding: '10px 12px', borderRadius: '8px',
    background: c.bg, marginBottom: '8px',
    border: `1px solid ${c.border}`,
  }}>
    <div style={{
      fontSize: '10px', fontWeight: 700, color: color || c.textDim,
      textTransform: 'uppercase', letterSpacing: '0.3px', marginBottom: '4px',
      display: 'flex', alignItems: 'center', gap: '4px',
    }}>{icon} {title}</div>
    <div style={{
      fontSize: '12px', lineHeight: 1.6, color: c.textDim,
      wordBreak: 'break-word',
    }}>{children}</div>
  </div>
}

function formatDuration(start, end) {
  const ms = end - start
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  const rem = s % 60
  return `${m}m ${rem}s`
}

/* ══════════════════════════════════════════════════════════
   INCIDENTS PANEL
   ══════════════════════════════════════════════════════════ */
function IncidentsPanel({ incidents }) {
  const active = incidents?.active || []
  const resolved = incidents?.resolved || []
  const [tab, setTab] = useState('active')
  const displayList = tab === 'active' ? active : resolved

  return <Card style={{ marginBottom: '20px' }}>
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      marginBottom: '16px',
    }}>
      <SectionTitle icon="📋">Incidents</SectionTitle>
      <div style={{ display: 'flex', gap: '4px' }}>
        {[
          { key: 'active', label: `Active (${active.length})`, color: active.length > 0 ? c.orange : c.textFaint },
          { key: 'resolved', label: `Resolved (${resolved.length})`, color: c.green },
        ].map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            padding: '5px 14px', borderRadius: '7px', fontSize: '11px', fontWeight: 600,
            background: tab === t.key ? `${t.color}18` : 'transparent',
            color: tab === t.key ? t.color : c.textFaint,
            border: `1px solid ${tab === t.key ? t.color + '40' : 'transparent'}`,
          }}>{t.label}</button>
        ))}
      </div>
    </div>

    {displayList.length === 0 ? (
      <div style={{
        textAlign: 'center', padding: '48px 0', color: c.textFaint,
      }}>
        <div style={{ fontSize: '48px', marginBottom: '10px' }}>
          {tab === 'active' ? '✨' : '📁'}
        </div>
        <div style={{ fontSize: '13px' }}>
          {tab === 'active' ? 'No active incidents — system is healthy' : 'No resolved incidents yet'}
        </div>
      </div>
    ) : (
      displayList.map((inc, i) => <IncidentCard key={inc.id || i} inc={inc} />)
    )}
  </Card>
}

/* ══════════════════════════════════════════════════════════
   MEMORY PANEL
   ══════════════════════════════════════════════════════════ */
function MemoryPanel({ memory }) {
  if (!memory) return null
  return <Card>
    <SectionTitle icon="🧠">Long-Term Memory</SectionTitle>
    <div style={{ display: 'flex', gap: '24px', marginBottom: '14px' }}>
      <div>
        <div style={{ fontSize: '28px', fontWeight: 800, color: c.accent }}>{memory.count || 0}</div>
        <div style={{ fontSize: '11px', color: c.textDim }}>Stored Incidents</div>
      </div>
      <div>
        <div style={{ fontSize: '11px', color: c.textDim }}>Fingerprint</div>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace", fontSize: '11px',
          color: c.textFaint, marginTop: '2px',
        }}>{memory.fingerprint || 'Not set'}</div>
      </div>
    </div>
    {memory.entries?.length > 0 && (
      <div style={{ maxHeight: '180px', overflowY: 'auto' }}>
        {memory.entries.slice(-5).map((e, i) => (
          <div key={i} style={{
            padding: '8px 12px', borderRadius: '7px', marginBottom: '5px',
            background: c.bg, fontSize: '11px', border: `1px solid ${c.border}`,
          }}>
            <div style={{ fontWeight: 600, color: c.text }}>{e.id}</div>
            <div style={{ color: c.textDim, marginTop: '2px' }}>{e.symptom}</div>
            <div style={{ color: c.textFaint, marginTop: '2px' }}>
              Fix: {e.fix} | Tags: {e.vectors?.join(', ')}
            </div>
          </div>
        ))}
      </div>
    )}
  </Card>
}

/* ══════════════════════════════════════════════════════════
   TOOLS PANEL
   ══════════════════════════════════════════════════════════ */
function ToolsPanel({ tools }) {
  if (!tools?.tools) return null
  const readonly = tools.tools.filter(t => ['read_file', 'grep_search', 'fetch_docs'].includes(t.name))
  const active = tools.tools.filter(t => !['read_file', 'grep_search', 'fetch_docs'].includes(t.name))

  return <Card>
    <SectionTitle icon="🔧">MCP Tools</SectionTitle>
    {[{ label: 'Read-Only (Safe)', items: readonly, color: c.green },
      { label: 'Active (Requires Permission)', items: active, color: c.orange }].map(group => (
      group.items.length > 0 && <div key={group.label} style={{ marginBottom: '12px' }}>
        <div style={{
          fontSize: '10px', fontWeight: 700, color: group.color,
          textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px',
        }}>{group.label}</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
          {group.items.map((t, i) => (
            <div key={i} style={{
              padding: '6px 12px', borderRadius: '7px',
              background: c.bg, border: `1px solid ${c.border}`,
            }}>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: '11px',
                fontWeight: 600, color: c.text,
              }}>{t.name}</div>
              <div style={{ fontSize: '10px', color: c.textFaint, marginTop: '1px' }}>
                {t.description}
              </div>
            </div>
          ))}
        </div>
      </div>
    ))}
  </Card>
}

/* ══════════════════════════════════════════════════════════
   ZERO TRUST SECURITY PANEL
   ══════════════════════════════════════════════════════════ */
function SecurityPanel({ security }) {
  if (!security) return null

  const modeColor = security.mode === 'ACTIVE' ? c.green : security.mode === 'AUDIT' ? c.orange : c.red

  return <Card style={{ marginBottom: '20px' }}>
    <SectionTitle icon="🔐" right={
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
        <Badge color={modeColor}>{security.mode} MODE</Badge>
        {security.stop_file_active && <Badge color={c.red}>⛔ STOP FILE</Badge>}
      </div>
    }>Zero Trust Security</SectionTitle>

    {/* Security Layers Grid */}
    <div style={{
      display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px', marginBottom: '16px',
    }}>
      {(security.security_layers || []).map((layer, i) => (
        <div key={i} style={{
          padding: '10px', borderRadius: '8px',
          background: c.bg, border: `1px solid ${c.border}`,
          textAlign: 'center', transition: 'border-color 0.3s',
        }}>
          <div style={{ fontSize: '16px', marginBottom: '4px', color: c.green }}>{layer.status}</div>
          <div style={{
            fontSize: '10px', fontWeight: 700, color: c.text,
            marginBottom: '2px',
          }}>{layer.name}</div>
          <div style={{
            fontSize: '9px', color: c.textFaint, lineHeight: 1.3,
          }}>{layer.description}</div>
        </div>
      ))}
    </div>

    {/* Agent Roles */}
    {security.agent_roles && (
      <div>
        <div style={{
          fontSize: '11px', fontWeight: 700, color: c.textDim,
          textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px',
        }}>Agent Role Permissions (Least Privilege)</div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {Object.entries(security.agent_roles).map(([role, info]) => {
            const roleColors = {
              supervisor: c.pink, triage: c.orange, detective: c.cyan,
              surgeon: c.accent, validator: c.green,
            }
            const roleIcons = {
              supervisor: '👑', triage: '🔍', detective: '🕵️',
              surgeon: '🔧', validator: '✅',
            }
            return <div key={role} style={{
              padding: '8px 14px', borderRadius: '8px',
              background: c.bg, border: `1px solid ${c.border}`,
              flex: '1', minWidth: '150px',
            }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px',
              }}>
                <span style={{ fontSize: '14px' }}>{roleIcons[role] || '🤖'}</span>
                <span style={{
                  fontSize: '11px', fontWeight: 700,
                  color: roleColors[role] || c.text,
                  textTransform: 'uppercase',
                }}>{role}</span>
                <Badge color={roleColors[role] || c.textDim} small>
                  {info.tool_count} tools
                </Badge>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
                {(info.tools_allowed || []).map((tool, j) => (
                  <span key={j} style={{
                    fontSize: '9px', padding: '1px 6px', borderRadius: '4px',
                    background: `${roleColors[role] || c.textDim}12`,
                    color: roleColors[role] || c.textDim,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>{tool}</span>
                ))}
                {(info.tools_allowed || []).length === 0 && (
                  <span style={{ fontSize: '9px', color: c.textFaint, fontStyle: 'italic' }}>
                    No tool access (routing only)
                  </span>
                )}
              </div>
            </div>
          })}
        </div>
      </div>
    )}
  </Card>
}

/* ══════════════════════════════════════════════════════════
   CONFIG PANEL — System Configuration at a glance
   ══════════════════════════════════════════════════════════ */
function ConfigPanel({ config }) {
  if (!config) return null

  const providerLabel = {
    bedrock_gateway: 'AWS Bedrock Gateway',
    anthropic: 'Anthropic Direct',
  }[config.llm_provider] || config.llm_provider

  // Shorten model name for display
  const shortModel = (config.model || 'unknown')
    .replace('global.anthropic.', '')
    .replace('claude-', 'Claude ')
    .replace(/-v\d+$/, '')

  const modeColor = config.mode === 'ACTIVE' ? c.green : config.mode === 'AUDIT' ? c.orange : c.red

  return <Card style={{ marginBottom: '20px' }}>
    <SectionTitle icon="⚙">System Configuration</SectionTitle>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '12px' }}>
      {/* LLM Provider */}
      <div style={{
        padding: '14px', borderRadius: '10px', background: c.bg,
        border: `1px solid ${c.border}`, textAlign: 'center',
      }}>
        <div style={{ fontSize: '10px', fontWeight: 700, color: c.textFaint, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
          LLM Provider
        </div>
        <div style={{ fontSize: '15px', fontWeight: 700, color: c.accent }}>{providerLabel}</div>
        <div style={{
          fontSize: '10px', color: c.textDim, marginTop: '4px',
          fontFamily: "'JetBrains Mono', monospace",
        }}>{shortModel}</div>
      </div>

      {/* Monitored Service */}
      <div style={{
        padding: '14px', borderRadius: '10px', background: c.bg,
        border: `1px solid ${c.border}`, textAlign: 'center',
      }}>
        <div style={{ fontSize: '10px', fontWeight: 700, color: c.textFaint, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
          Monitored Service
        </div>
        <div style={{
          fontSize: '13px', fontWeight: 700, color: c.cyan,
          fontFamily: "'JetBrains Mono', monospace",
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{config.service_source_path || '/app/workspace'}</div>
        <div style={{ fontSize: '10px', color: c.textDim, marginTop: '4px' }}>
          {(config.watch_paths || []).length} watch path{(config.watch_paths || []).length !== 1 ? 's' : ''}
        </div>
      </div>

      {/* Operating Mode */}
      <div style={{
        padding: '14px', borderRadius: '10px', background: c.bg,
        border: `1px solid ${modeColor}30`, textAlign: 'center',
      }}>
        <div style={{ fontSize: '10px', fontWeight: 700, color: c.textFaint, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
          Operating Mode
        </div>
        <div style={{ fontSize: '20px', fontWeight: 800, color: modeColor }}>{config.mode}</div>
        <div style={{ fontSize: '10px', color: c.textDim, marginTop: '4px' }}>
          {config.mode === 'ACTIVE' ? 'Full autonomous operation' : config.mode === 'AUDIT' ? 'Log only, no execution' : 'All actions disabled'}
        </div>
      </div>
    </div>

    {/* Secondary config row */}
    <div style={{
      display: 'flex', flexWrap: 'wrap', gap: '8px', fontSize: '11px',
      justifyContent: 'center',
    }}>
      {[
        { label: 'Watch Paths', value: (config.watch_paths || []).join(', ') || 'none', color: c.textDim },
        { label: 'Poll Interval', value: `${config.poll_interval || 5}s`, color: c.textDim },
        { label: 'Cost Limit', value: `$${config.max_cost_10min || 5}/10min`, color: c.textDim },
        { label: 'Max Retries', value: config.max_retries || 3, color: c.textDim },
        { label: 'Restart Cooldown', value: `${config.restart_cooldown || 600}s`, color: c.textDim },
        { label: 'Log Level', value: config.log_level || 'INFO', color: c.textDim },
      ].map((item, i) => (
        <div key={i} title={String(item.value)} style={{
          padding: '5px 10px', borderRadius: '6px',
          background: c.surfaceAlt, border: `1px solid ${c.border}`,
          display: 'flex', gap: '6px', alignItems: 'center',
        }}>
          <span style={{ color: c.textFaint, fontWeight: 600 }}>{item.label}:</span>
          <span style={{
            color: item.color, fontFamily: "'JetBrains Mono', monospace",
            fontWeight: 500,
          }}>{item.value}</span>
        </div>
      ))}
    </div>
  </Card>
}

/* ══════════════════════════════════════════════════════════
   MAIN APP
   ══════════════════════════════════════════════════════════ */
export default function App() {
  const { data: status, refresh: refreshStatus } = useApi('/status', 3000)
  const { data: incidents, refresh: refreshInc } = useApi('/incidents', 3000)
  const { data: memory, refresh: refreshMem } = useApi('/memory', 10000)
  const { data: tools } = useApi('/tools')
  const { data: security } = useApi('/security', 15000)
  const { data: config } = useApi('/config')

  const refreshAll = () => { refreshStatus(); refreshInc(); refreshMem() }

  return <div style={{ background: c.bg, color: c.text, minHeight: '100vh' }}>
    <GlobalStyles />
    <Header status={status} onRefresh={refreshAll} />

    <main style={{ maxWidth: '1440px', margin: '0 auto', padding: '20px 28px' }}>
      {/* Status Metrics Row */}
      <StatusRow status={status} />

      {/* System Configuration */}
      <ConfigPanel config={config} />

      {/* Watcher + Trigger */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: '20px',
      }}>
        <WatcherControl running={status?.watcher_running} onToggle={refreshAll} />
        <div style={{ fontSize: '11px', color: c.textFaint }}>
          Auto-refreshing every 3s
        </div>
      </div>

      <TriggerPanel onTrigger={refreshAll} />

      {/* Zero Trust Security Panel */}
      <SecurityPanel security={security} />

      {/* Incidents */}
      <IncidentsPanel incidents={incidents} />

      {/* Bottom row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <MemoryPanel memory={memory} />
        <ToolsPanel tools={tools} />
      </div>
    </main>

    <footer style={{
      textAlign: 'center', padding: '20px', color: c.textFaint,
      fontSize: '11px', borderTop: `1px solid ${c.border}`,
      marginTop: '40px',
    }}>
      Sentry v1.0 — Self-Healing Server Monitor — Zero Trust Security
    </footer>
  </div>
}
