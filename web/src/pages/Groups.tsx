import { useState } from 'react'
import type { Service } from '../App'

export default function Groups({ services }: { services: Service[] }) {
  const [busy, setBusy] = useState<string | null>(null)

  const setStatus = async (groupID: string, status: string) => {
    setBusy(groupID)
    await fetch(`/api/v1/groups/${groupID}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    })
    setBusy(null)
  }

  return (
    <div className="space-y-6">
      {services.map((s) => (
        <div key={s.id}>
          <h2 className="mb-2 font-semibold">
            {s.name} <span className="text-xs text-slate-500">:{s.port}</span>
          </h2>
          <table className="w-full rounded-xl border border-slate-800 bg-slate-900 text-sm">
            <thead className="text-left text-xs uppercase text-slate-400">
              <tr>
                <th className="p-2">Group</th>
                <th className="p-2">Status</th>
                <th className="p-2">Weight</th>
                <th className="p-2">Flows</th>
                <th className="p-2">Checker?</th>
                <th className="p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {s.groups.map((g) => (
                <tr key={g.id} className="border-t border-slate-800">
                  <td className="p-2 font-mono text-xs">{g.id.slice(0, 16)}…</td>
                  <td className="p-2">{g.status}</td>
                  <td className="p-2">{g.weight.toFixed(2)}</td>
                  <td className="p-2">{g.flows}</td>
                  <td className="p-2">{g.is_checker == null ? '—' : g.is_checker ? '✓' : '✗'}</td>
                  <td className="flex gap-1 p-2">
                    <button
                      disabled={busy === g.id}
                      onClick={() =>
                        fetch(`/api/v1/services/${s.id}/groups/${g.id}`, {
                          method: 'PATCH',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({ is_checker: true }),
                        })
                      }
                      className="rounded bg-emerald-700 px-2 py-0.5 text-xs hover:bg-emerald-600"
                    >
                      checker
                    </button>
                    <button
                      disabled={busy === g.id}
                      onClick={() =>
                        fetch(`/api/v1/services/${s.id}/groups/${g.id}`, {
                          method: 'PATCH',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({ is_checker: false }),
                        })
                      }
                      className="rounded bg-slate-700 px-2 py-0.5 text-xs hover:bg-slate-600"
                    >
                      not checker
                    </button>
                    <button
                      disabled={busy === g.id}
                      onClick={() => setStatus(g.id, 'banned')}
                      className="rounded bg-red-800 px-2 py-0.5 text-xs hover:bg-red-700"
                    >
                      ban
                    </button>
                    <button
                      disabled={busy === g.id}
                      onClick={() => setStatus(g.id, 'allowed')}
                      className="rounded bg-sky-800 px-2 py-0.5 text-xs hover:bg-sky-700"
                    >
                      allow
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      {services.every((s) => s.groups.length === 0) && (
        <p className="text-slate-400">No groups yet.</p>
      )}
    </div>
  )
}
