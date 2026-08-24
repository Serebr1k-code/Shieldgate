import { useEffect, useState } from 'react'

interface BoardCfg {
  type: string
  url: string
  token: string
  our_ip: string
  task_ports: Record<string, number>
}

interface Settings {
  board: BoardCfg
  round_duration_minutes: number
  flag_regex: string
  ban_fraction: number
  mirror_enabled: boolean
}

const EMPTY: Settings = {
  board: { type: 'forcad', url: '', token: '', our_ip: '', task_ports: {} },
  round_duration_minutes: 2,
  flag_regex: '[A-Za-z0-9]{31}=',
  ban_fraction: 0.25,
  mirror_enabled: true,
}

export default function SettingsPage() {
  const [values, setValues] = useState<Settings>(EMPTY)
  const [portsText, setPortsText] = useState('')
  const [status, setStatus] = useState<'idle' | 'saving' | 'ok' | 'error'>('idle')
  const [error, setError] = useState('')

  useEffect(() => {
    fetch('/api/v1/settings')
      .then((r) => r.json())
      .then((s: Partial<Settings>) => {
        const merged = { ...EMPTY, ...s, board: { ...EMPTY.board, ...s.board } }
        setValues(merged)
        setPortsText(
          Object.entries(merged.board.task_ports)
            .map(([k, v]) => `${k}=${v}`)
            .join('\n'),
        )
      })
      .catch(() => {})
  }, [])

  const parsePorts = (text: string): Record<string, number> => {
    const out: Record<string, number> = {}
    for (const line of text.split('\n')) {
      const m = line.trim().match(/^([A-Za-z0-9_\-]+)\s*[:=]\s*(\d+)\s*$/)
      if (m) out[m[1].toLowerCase()] = parseInt(m[2], 10)
    }
    return out
  }

  const save = async () => {
    setStatus('saving')
    setError('')
    const payload: Settings = {
      ...values,
      board: { ...values.board, task_ports: parsePorts(portsText) },
    }
    const r = await fetch('/api/v1/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    if (r.ok) {
      setStatus('ok')
      setTimeout(() => setStatus('idle'), 3000)
    } else {
      const body = await r.json().catch(() => ({ error: r.statusText }))
      setStatus('error')
      setError(body.error ?? `HTTP ${r.status}`)
    }
  }

  const input =
    'w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm focus:border-sky-500 outline-none'

  return (
    <div className="max-w-2xl space-y-6">
      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5 space-y-4">
        <h2 className="font-semibold">Scoreboard</h2>

        <label className="block">
          <span className="mb-1 block text-sm text-slate-400">Type</span>
          <select
            value={values.board.type}
            onChange={(e) => setValues({ ...values, board: { ...values.board, type: e.target.value } })}
            className={input}
          >
            <option value="forcad">ForcAD</option>
            <option value="ctfd">CTFd</option>
            <option value="faust">FAUST gameserver</option>
          </select>
        </label>

        <label className="block">
          <span className="mb-1 block text-sm text-slate-400">Board URL</span>
          <input
            value={values.board.url}
            placeholder="https://scoreboard.example.com"
            onChange={(e) => setValues({ ...values, board: { ...values.board, url: e.target.value } })}
            className={input}
          />
        </label>

        <div className="grid grid-cols-2 gap-4">
          <label className="block">
            <span className="mb-1 block text-sm text-slate-400">Our IP</span>
            <input
              value={values.board.our_ip}
              placeholder="10.70.20.2"
              onChange={(e) =>
                setValues({ ...values, board: { ...values.board, our_ip: e.target.value } })
              }
              className={input}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-sm text-slate-400">API token (optional)</span>
            <input
              value={values.board.token}
              type="password"
              onChange={(e) => setValues({ ...values, board: { ...values.board, token: e.target.value } })}
              className={input}
            />
          </label>
        </div>

        <label className="block">
          <span className="mb-1 block text-sm text-slate-400">
            Task ports — one per line, <code>name=port</code>
          </span>
          <textarea
            value={portsText}
            rows={5}
            placeholder={'xingyuan=8000\npipeline=8081'}
            onChange={(e) => setPortsText(e.target.value)}
            className={`${input} font-mono`}
          />
        </label>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5 space-y-4">
        <h2 className="font-semibold">Engine</h2>
        <div className="grid grid-cols-2 gap-4">
          <label className="block">
            <span className="mb-1 block text-sm text-slate-400">Round duration (minutes)</span>
            <input
              type="number"
              min={1}
              value={values.round_duration_minutes}
              onChange={(e) =>
                setValues({ ...values, round_duration_minutes: parseInt(e.target.value, 10) || 2 })
              }
              className={input}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-sm text-slate-400">Ban fraction (0–1)</span>
            <input
              type="number"
              step="0.05"
              min={0.05}
              max={0.95}
              value={values.ban_fraction}
              onChange={(e) => setValues({ ...values, ban_fraction: parseFloat(e.target.value) || 0.25 })}
              className={input}
            />
          </label>
        </div>
        <label className="block">
          <span className="mb-1 block text-sm text-slate-400">Flag regex</span>
          <input
            value={values.flag_regex}
            onChange={(e) => setValues({ ...values, flag_regex: e.target.value })}
            className={`${input} font-mono`}
          />
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={values.mirror_enabled}
            onChange={(e) => setValues({ ...values, mirror_enabled: e.target.checked })}
            className="size-4 accent-sky-600"
          />
          <span className="text-sm text-slate-300">Mirror banned packets to other teams</span>
        </label>
      </section>

      <div className="flex items-center gap-4">
        <button
          onClick={save}
          disabled={status === 'saving'}
          className="rounded-md bg-sky-600 px-5 py-2.5 text-sm font-medium hover:bg-sky-500 disabled:opacity-50"
        >
          {status === 'saving' ? 'Applying…' : 'Save & connect'}
        </button>
        {status === 'ok' && <span className="text-sm text-emerald-400">Applied ✓</span>}
        {status === 'error' && <span className="text-sm text-red-400">{error}</span>}
      </div>
      <p className="text-xs text-slate-500">
        Saving connects to the board immediately and installs nftables interception for every
        service port. Configuration persists across restarts.
      </p>
    </div>
  )
}
