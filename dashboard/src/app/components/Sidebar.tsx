'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Activity, ShieldAlert, Settings, BarChart2, Globe } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function Sidebar() {
  const pathname = usePathname();

  const navItems = [
    { name: 'Live Telemetry', href: '/', icon: Activity },
    { name: 'Threat Intelligence', href: '/intelligence', icon: ShieldAlert },
    { name: 'Infrastructure', href: '/infrastructure', icon: Globe },
    { name: 'Statistics', href: '/stats', icon: BarChart2 },
    { name: 'Settings', href: '/settings', icon: Settings },
  ];

  return (
    <div className="w-64 h-screen glass-panel fixed left-0 top-0 flex flex-col z-50">
      <div className="flex items-center gap-3 p-6 border-b border-cyber-border">
        <Shield className="w-8 h-8 text-cyber-accent" />
        <h1 className="text-lg font-bold glow-text tracking-wider">OCTO-PALM</h1>
      </div>
      
      <nav className="flex-1 py-6 px-4 space-y-2">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          
          return (
            <Link
              key={item.name}
              href={item.href}
              className={twMerge(
                clsx(
                  'flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group',
                  isActive
                    ? 'bg-cyber-accent/10 text-cyber-accent shadow-[inset_4px_0_0_0_var(--color-cyber-accent)]'
                    : 'text-cyber-muted hover:bg-cyber-border/30 hover:text-cyber-text'
                )
              )}
            >
              <Icon className={clsx("w-5 h-5", isActive ? "text-cyber-accent" : "group-hover:text-cyber-text")} />
              <span className="font-medium text-sm">{item.name}</span>
            </Link>
          );
        })}
      </nav>
      
      <div className="p-4 border-t border-cyber-border">
        <div className="flex items-center gap-3 px-4 py-3 bg-cyber-bg/50 rounded-lg">
          <div className="w-2 h-2 rounded-full bg-cyber-accent animate-pulse shadow-[0_0_8px_var(--color-cyber-accent)]" />
          <span className="text-xs font-semibold tracking-widest text-cyber-muted">SYSTEM ONLINE</span>
        </div>
      </div>
    </div>
  );
}
