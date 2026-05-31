'use client';

import { ShieldAlert, AlertTriangle, AlertCircle, Clock, Globe } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface ThreatProps {
  threat: {
    id: number;
    timestamp: string;
    threat_type: string;
    details: string;
    severity: 'critical' | 'high' | 'medium';
    url: string;
    risk_score: number;
    source: string;
  };
}

export function ThreatCard({ threat }: ThreatProps) {
  const isCritical = threat.severity === 'critical';
  const isHigh = threat.severity === 'high';
  
  return (
    <div className={twMerge(
      clsx(
        "p-5 rounded-xl transition-all duration-300 hover:scale-[1.01]",
        isCritical ? "glass-panel-danger" : isHigh ? "glass-panel-accent" : "glass-panel"
      )
    )}>
      <div className="flex justify-between items-start mb-3">
        <div className="flex items-center gap-3">
          <div className={clsx(
            "p-2 rounded-lg",
            isCritical ? "bg-cyber-danger/20 text-cyber-danger" : 
            isHigh ? "bg-cyber-warning/20 text-cyber-warning" : 
            "bg-cyber-accent/20 text-cyber-accent"
          )}>
            {isCritical ? <ShieldAlert className="w-5 h-5" /> : 
             isHigh ? <AlertTriangle className="w-5 h-5" /> : 
             <AlertCircle className="w-5 h-5" />}
          </div>
          <div>
            <h3 className={clsx(
              "font-bold uppercase tracking-wider text-sm",
              isCritical ? "text-cyber-danger glow-text-danger" : "text-cyber-text"
            )}>
              {threat.threat_type.replace(/_/g, ' ')}
            </h3>
            <div className="flex items-center gap-2 text-xs text-cyber-muted mt-1">
              <Clock className="w-3 h-3" />
              <span>{new Date(threat.timestamp).toLocaleString()}</span>
              <span>•</span>
              <span className="uppercase">{threat.source}</span>
            </div>
          </div>
        </div>
        <div className={clsx(
          "px-3 py-1 rounded-full text-xs font-bold font-mono border",
          isCritical ? "border-cyber-danger text-cyber-danger bg-cyber-danger/10" : 
          "border-cyber-accent text-cyber-accent bg-cyber-accent/10"
        )}>
          SCORE: {threat.risk_score}
        </div>
      </div>
      
      <div className="bg-cyber-bg/50 p-3 rounded-lg border border-cyber-border mb-3 font-mono text-sm overflow-x-auto whitespace-nowrap">
        <span className="text-cyber-muted mr-2">TARGET:</span>
        <span className="text-cyber-text">{threat.url}</span>
      </div>
      
      <div className="text-sm text-cyber-muted">
        {threat.details.split(';').map((detail, i) => (
          <div key={i} className="flex items-start gap-2 mb-1">
            <div className="w-1.5 h-1.5 rounded-full bg-cyber-border mt-1.5 shrink-0" />
            <span>{detail.trim()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
