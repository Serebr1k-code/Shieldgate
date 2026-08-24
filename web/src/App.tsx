import { useEffect, useState } from 'react'
import Dashboard from './pages/Dashboard'
import Flows from './pages/Flows'
import Groups from './pages/Groups'
import SettingsPage from './pages/Settings'

export interface Service {
  id: string
  name: string
  port: number
  protocol: string
  phase: 'idle' | 'learning' | 'filtering' | 'optimizing'
  groups: {
    id: string
    status: 'candidate' | 'allowed' | 'banned' | 'temp_banned'
    weight: number
    flows: number
    is_checker?: boolean | null
  }[]
}

export interface WsEvent {
  type: string
  service_id?: string
  message?: string
  at: string
}

const TABS = ['Dashboard', 'Flows', 'Groups', 'Settings'] as const
type Tab = (typeof TABS)[number]

export default function App() {
  const [tab, setTab] = useState<Tab>('Dashboard')
  const [services, setServices] = useState<Service[]>([])
  const [events, setEvents] = useState<WsEvent[]>([])

  const refresh = async () => {
    const r = await fetch('/api/v1/services')
    if (r.ok) setServices(await r.json())
  }

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 10_000)
    const ws = new WebSocket(`ws://${location.host}/ws`)
    ws.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as WsEvent
        setEvents((prev) => [ev, ...prev].slice(0, 100))
        if (ev.type === 'phase.change' || ev.type === 'group.update') refresh()
      } catch { /* ignore */ }
    }
    return () => { clearInterval(t); ws.close() }
  }, [])

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 px-6 py-4 flex items-center gap-8">
        <h1 className="text-xl font-bold tracking-tight">
          🛡 ShieldGate
        </h1>
        <nav className="flex gap-1">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-3 py-1.5 rounded-md text-sm ${
                tab === t ? 'bg-sky-600 text-white' : 'hover:bg-slate-800 text-slate-300'
              }`}
            >
              {t}
            </button>
          ))}
        </nav>
      </header>
      <main className="p-6">
        {tab === 'Dashboard' && <Dashboard services={services} events={events} />}
        {tab === 'Flows' && <Flows />}
        {tab === 'Groups' && <Groups services={services} />}
        {tab === 'Settings' && <SettingsPage />}
      </main>
    </div>
  )
}
