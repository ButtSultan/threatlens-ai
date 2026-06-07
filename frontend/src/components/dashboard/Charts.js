import React from 'react';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, BarChart, Bar, 
} from 'recharts';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#94a3b8',
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs shadow-xl">
      {label && <p className="text-slate-400 mb-1">{label}</p>}
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color || p.fill }} className="font-medium">
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
};

export function SeverityDonut({ data }) {
  if (!data?.length) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        No data yet
      </div>
    );
  }

  return (
    <div className="flex items-center gap-6">
      <ResponsiveContainer width={160} height={160}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={72}
            paddingAngle={3}
            dataKey="count"
            nameKey="severity"
          >
            {data.map((entry, i) => (
              <Cell
                key={i}
                fill={SEVERITY_COLORS[entry.severity] || '#94a3b8'}
                stroke="transparent"
              />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="flex flex-col gap-2 flex-1">
        {data.map((entry, i) => (
          <div key={i} className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <div
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: SEVERITY_COLORS[entry.severity] || '#94a3b8' }}
              />
              <span className="text-slate-400 capitalize">{entry.severity}</span>
            </div>
            <span className="font-semibold text-slate-200">{entry.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function DetectionTrendChart({ data }) {
  if (!data?.length) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        No trend data yet
      </div>
    );
  }

  // Group by date
  const byDate = {};
  data.forEach(({ date, severity, count }) => {
    if (!byDate[date]) byDate[date] = { date };
    byDate[date][severity] = (byDate[date][severity] || 0) + count;
  });
  const chartData = Object.values(byDate).sort((a, b) => a.date.localeCompare(b.date));
  const severities = [...new Set(data.map(d => d.severity))];

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={chartData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
        <defs>
          {severities.map(s => (
            <linearGradient key={s} id={`grad-${s}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={SEVERITY_COLORS[s]} stopOpacity={0.3} />
              <stop offset="95%" stopColor={SEVERITY_COLORS[s]} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        {severities.map(s => (
          <Area
            key={s}
            type="monotone"
            dataKey={s}
            stroke={SEVERITY_COLORS[s]}
            fill={`url(#grad-${s})`}
            strokeWidth={2}
            dot={false}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function MITREBarChart({ data }) {
  if (!data?.length) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        No MITRE data yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 40 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis
          dataKey="tactic"
          tick={{ fontSize: 9, fill: '#64748b' }}
          axisLine={false}
          tickLine={false}
          angle={-35}
          textAnchor="end"
          interval={0}
        />
        <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Bar dataKey="count" fill="#0ea5e9" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
