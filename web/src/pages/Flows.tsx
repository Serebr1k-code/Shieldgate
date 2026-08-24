import { useEffect, useState } from 'react'

interface Flow {
  id: string
  src: string
  dst: string
  src_port: number
  dst_port: number
  service: string
  bytes_in: number
  bytes_out: number
  status: string
  group_id: string
  flag_seen: boolean
}

export default function Flows() {
  const [flows, setFlows] = useState<Flow[]>([])
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState<Flow | null>(null)

  useEffect(() => {
    const load = async () => {
      const r = await fetch('/api/v1/flows?limit=200')
      if (r.ok) setFlows(await r.json())
    }
    load()
    const t = setInterval(load, 3000)
    return () => clearInterval(t)
  }, [])

  const shown = flows.filter(
    (f) =>
      filter === '' ||
      f.src.includes(filter) ||
      f.dst.includes(filter) ||
      f.service.includes(filter),
  )

  const openPayload = async (f: Flow) => {
    const r = await fetch(`/api/v1/flows/${f.id}`)
    if (!r.ok) return
    const detail = await r.json()
    setSelected({ ...f, ...detail })
  }

  const hexdump = (data: number[] | undefined) => {
    if (!data?.length) return '(empty)'
    const bytes = Uint8Array.from(data)
    let out = ''
    for (let i = 0; i < bytes.length; i += 16) {
      const row = [...bytes.slice(i, i + 16)]
      const hex = row.map((b) => b.toString(16).padStart(2, '0')).join(' ')
      const ascii = row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('')
      out += `${i.toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  |${ascii}|\n`
    }
    return out
  }

  return (
    <div className="space-y-4">
      <input
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="filter by IP or service…"
        className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
      />
      <div className="overflow-auto rounded-xl border border-slate-800 bg-slate-900">
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-400">
            <tr>
              <th className="p-2">Source</th>
              <th className="p-2">Destination</th>
              <th className="p-2">Service</th>
              <th className="p-2">In/Out</th>
              <th className="p-2">Status</th>
              <th className="p-2">Flag</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => (
              <tr
                key={f.id}
                onClick={() => openPayload(f)}
                className="cursor-pointer border-t border-slate-800 hover:bg-slate-800/50"
              >
                <td className="p-2 font-mono text-xs">
                  {f.src}:{f.src_port}
                </td>
                <td className="p-2 font-mono text-xs">
                  {f.dst}:{f.dst_port}
                </td>
                <td className="p-2">{f.service}</td>
                <td className="p-2">
                  {f.bytes_in} / {f.bytes_out}
                </td>
                <td className="p-2">{f.status}</td>
                <td className="p-2">{f.flag_seen ? '🚩' : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="font-semibold">Payload — flow {selected.id.slice(0, 12)}…</h3>
            <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white">
              ✕
            </button>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <pre className="overflow-auto rounded bg-slate-950 p-3 text-xs text-emerald-300">
              {hexdump((selected as any).payload_in)}
            </pre>
            <pre className="overflow-auto rounded bg-slate-950 p-3 text-xs text-sky-300">
              {hexdump((selected as any).payload_out)}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
