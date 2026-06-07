import React from 'react';

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'cyber', trend }) {
  const colorMap = {
    cyber:    { bg: 'bg-cyber-500/10',    border: 'border-cyber-500/20',    icon: 'text-cyber-400' },
    red:      { bg: 'bg-red-500/10',      border: 'border-red-500/20',      icon: 'text-red-400' },
    orange:   { bg: 'bg-orange-500/10',   border: 'border-orange-500/20',   icon: 'text-orange-400' },
    yellow:   { bg: 'bg-yellow-500/10',   border: 'border-yellow-500/20',   icon: 'text-yellow-400' },
    green:    { bg: 'bg-green-500/10',    border: 'border-green-500/20',    icon: 'text-green-400' },
    purple:   { bg: 'bg-purple-500/10',   border: 'border-purple-500/20',   icon: 'text-purple-400' },
    slate:    { bg: 'bg-slate-500/10',    border: 'border-slate-500/20',    icon: 'text-slate-400' },
  };
  const c = colorMap[color] || colorMap.cyber;

  return (
    <div className="stat-card group">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</p>
          <p className="text-3xl font-bold text-slate-100 mt-1 font-display">
            {value ?? '—'}
          </p>
          {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
        </div>
        {Icon && (
          <div className={`p-2.5 rounded-xl border ${c.bg} ${c.border}`}>
            <Icon className={`w-5 h-5 ${c.icon}`} />
          </div>
        )}
      </div>
      {trend !== undefined && (
        <div className="flex items-center gap-1 mt-1">
          <span className={`text-xs font-medium ${trend >= 0 ? 'text-green-400' : 'text-red-400'}`}>
            {trend >= 0 ? '+' : ''}{trend}%
          </span>
          <span className="text-xs text-slate-500">vs yesterday</span>
        </div>
      )}
    </div>
  );
}
