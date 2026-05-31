'use client';

import { useEffect, useState } from 'react';
import { Sidebar } from './components/Sidebar';
import { ThreatCard } from './components/ThreatCard';
import { Shield, Target, AlertOctagon, Activity } from 'lucide-react';

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [threats, setThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsRes = await fetch('http://127.0.0.1:8000/alerts/stats');
        if (statsRes.ok) setStats(await statsRes.json());
        
        const liveRes = await fetch('http://127.0.0.1:8000/alerts/live');
        if (liveRes.ok) setThreats((await liveRes.json()).data || []);
      } catch (err) {
        console.error("Failed to fetch telemetry:", err);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-cyber-bg text-cyber-text flex font-sans selection:bg-cyber-accent/30 selection:text-white">
      <Sidebar />
      
      <main className="flex-1 ml-64 p-8 max-w-7xl">
        <header className="mb-10 flex justify-between items-end border-b border-cyber-border pb-6">
          <div>
            <h2 className="text-3xl font-bold tracking-tight glow-text mb-2">Live Telemetry</h2>
            <p className="text-cyber-muted font-mono text-sm">Real-time threat monitoring and network interception</p>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 glass-panel rounded-lg">
            <Activity className="w-5 h-5 text-cyber-accent animate-pulse" />
            <span className="font-mono text-sm font-bold text-cyber-accent">LIVE</span>
          </div>
        </header>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
          <div className="glass-panel p-6 rounded-xl relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
              <Target className="w-24 h-24" />
            </div>
            <h3 className="text-cyber-muted font-bold text-sm tracking-widest mb-1">TOTAL THREATS</h3>
            <div className="text-4xl font-bold glow-text mb-2">{stats?.total || 0}</div>
            <div className="text-xs font-mono text-cyber-accent">+{stats?.recent_24h || 0} in last 24h</div>
          </div>
          
          <div className="glass-panel-danger p-6 rounded-xl relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-cyber-danger">
              <AlertOctagon className="w-24 h-24" />
            </div>
            <h3 className="text-cyber-danger font-bold text-sm tracking-widest mb-1 glow-text-danger">CRITICAL SEVERITY</h3>
            <div className="text-4xl font-bold text-cyber-danger glow-text-danger mb-2">{stats?.critical || 0}</div>
            <div className="text-xs font-mono text-cyber-danger/70">Immediate block required</div>
          </div>
          
          <div className="glass-panel-accent p-6 rounded-xl relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-cyber-accent">
              <Shield className="w-24 h-24" />
            </div>
            <h3 className="text-cyber-accent font-bold text-sm tracking-widest mb-1 glow-text">HIGH SEVERITY</h3>
            <div className="text-4xl font-bold text-cyber-accent glow-text mb-2">{stats?.high || 0}</div>
            <div className="text-xs font-mono text-cyber-accent/70">Requires investigation</div>
          </div>
        </div>

        {/* Two Column Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 space-y-6">
            <h3 className="font-bold text-xl tracking-wide flex items-center gap-3 mb-6">
              <span className="w-2 h-6 bg-cyber-accent rounded-full shadow-[0_0_10px_var(--color-cyber-accent)]" />
              Latest Interceptions
            </h3>
            
            {loading ? (
              <div className="glass-panel p-10 flex justify-center rounded-xl">
                <Activity className="w-10 h-10 text-cyber-accent animate-spin" />
              </div>
            ) : threats.length === 0 ? (
              <div className="glass-panel p-10 text-center rounded-xl text-cyber-muted font-mono">
                No active threats detected in the telemetry stream.
              </div>
            ) : (
              <div className="space-y-4">
                {threats.map((threat) => (
                  <ThreatCard key={threat.id} threat={threat} />
                ))}
              </div>
            )}
          </div>
          
          <div className="space-y-6">
            <h3 className="font-bold text-xl tracking-wide flex items-center gap-3 mb-6">
              <span className="w-2 h-6 bg-cyber-warning rounded-full shadow-[0_0_10px_var(--color-cyber-warning)]" />
              Top Targeted Domains
            </h3>
            
            <div className="glass-panel rounded-xl p-5">
              {stats?.top_domains?.length ? (
                <div className="space-y-4">
                  {stats.top_domains.map((d: any, idx: number) => (
                    <div key={d.domain} className="flex justify-between items-center border-b border-cyber-border/50 pb-3 last:border-0 last:pb-0">
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-cyber-muted text-xs">{idx + 1}</span>
                        <span className="font-mono text-sm truncate max-w-[150px]">{d.domain}</span>
                      </div>
                      <span className="bg-cyber-border/50 text-cyber-text px-2 py-0.5 rounded text-xs font-mono">
                        {d.count} hits
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-cyber-muted font-mono text-sm text-center py-5">
                  Not enough data collected
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
