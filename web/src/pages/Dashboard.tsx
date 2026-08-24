import type { Service, WsEvent } from '../App'

const PHASE_COLORS: Record<Service['phase'], string> = {
  idle: 'bg-slate-600',
  learning: 'bg-amber-500',
  filtering: 'bg-emerald-500',
  optimizing: 'bg-sky-500',
}

const GROUP_BADGES: Record<string, string> = {
  candidate: 'bg-slate-700 text-slate-200',
  allowed: 'bg-emerald-800 text-emerald-200',
  banned: 'bg-red-900 text-red-200',
  temp_banned: 'bg-amber-800 text-amber-100',
}

export default function Dashboard({
  services,
  events,
}: {
  services: Service[]
  events: WsEvent[]
}) {
  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
      <section className="xl:col-span-2 grid gap-4 md:grid-cols-2">
        {services.length === 0 && (
          <p className="text-slate-400">No services discovered yet — check board connection.</p>
        )}
        {services.map((s) => {
          const counts = {
            allowed: s.groups.filter((g) => g.status === 'allowed').length,
            banned: s.groups.filter((g) => g.status === 'banned').length,
            temp: s.groups.filter((g) => g.status === 'temp_banned').length,
          }
          return (
            <div key={s.id} className="rounded-xl border border-slate-800 bg-slate-900 p-4">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h2 className="font-semibold">{s.name}</h2>
                  <p className="text-xs text-slate-400">
                    :{s.port}/{s.protocol}
                  </p>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-xs text-white ${PHASE_COLORS[s.phase]}`}
                >
                  {s.phase}
                </span>
              </div>
              <div className="grid grid-cols-4 gap-2 text-center text-sm">
                <Stat label="groups" value={s.groups.length} />
                <Stat label="allowed" value={counts.allowed} tone="text-emerald-400" />
                <Stat label="banned" value={counts.banned} tone="text-red-400" />
                <Stat label="temp" value={counts.temp} tone="text-amber-300" />
              </div>
            </div>
          )
        })}
      </section>

      <aside className="rounded-xl border border-slate-800 bg-slate-900 p-4 max-h-[70vh] overflow-auto">
        <h2 className="font-semibold mb-2 text-sm">Live events</h2>
        {events.length === 0 && <p className="text-slate-500 text-sm">waiting…</p>}
        <ul className="space-y-1.5 text-xs">
          {events.map((ev, i) => (
            <li key={i} className="border-b border-slate-800 pb-1">
              <span className="text-sky-400">{ev.type}</span>{' '}
              {ev.service_id && <span className="text-slate-400">{ev.service_id}</span>}{' '}
              <span>{ev.message}</span>
            </li>
          ))}
        </ul>
      </aside>

      <section className="xl:col-span-3 rounded-xl border border-slate-800 bg-slate-900 p-4 overflow-auto">
        <h2 className="font-semibold mb-3">Flow groups</h2>
        <table className="w-full text-sm">
          <thead className="text-left text-slate-400 text-xs uppercase">
            <tr>
              <th className="py-1 pr-4">Service</th>
              <th className="py-1 pr-4">Group</th>
              <th className="py-1 pr-4">Status</th>
              <th className="py-1 pr-4">Weight</th>
              <th className="py-1 pr-4">Flows</th>
              <th className="py-1">Checker?</th>
            </tr>
          </thead>
          <tbody>
            {services.flatMap((s) =>
              s.groups.map((g) => (
                <tr key={g.id} className="border-t border-slate-800">
                  <td className="py-1.5 pr-4">{s.name}</td>
                  <td className="pr-4 font-mono text-xs">{g.id.slice(0, 10)}…</td>
                  <td className="pr-4">
                    <span className={`px-1.5 py-0.5 rounded text-xs ${GROUP_BADGES[g.status]}`}>
                      {g.status}
                    </span>
                  </td>
                  <td className="pr-4">{g.weight.toFixed(2)}</td>
                  <td className="pr-4">{g.flows}</td>
                  <td>{g.is_checker == null ? '—' : g.is_checker ? '✓' : '✗'}</td>
                </tr>
              )),
            )}
          </tbody>
        </table>
      </section>
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded bg-slate-950/60 py-2">
      <div className={`text-lg font-semibold ${tone ?? ''}`}>{value}</div>
      <div className="text-[10px] uppercase text-slate-500">{label}</div>
    </div>
  )
}
