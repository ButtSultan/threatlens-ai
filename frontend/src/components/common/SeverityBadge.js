import React from 'react';

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', cls: 'badge-critical', dot: 'bg-red-400' },
  high:     { label: 'High',     cls: 'badge-high',     dot: 'bg-orange-400' },
  medium:   { label: 'Medium',   cls: 'badge-medium',   dot: 'bg-yellow-400' },
  low:      { label: 'Low',      cls: 'badge-low',      dot: 'bg-green-400' },
  info:     { label: 'Info',     cls: 'badge-info',     dot: 'bg-slate-400' },
};

const STATUS_CONFIG = {
  open:        { label: 'Open',        cls: 'status-open' },
  in_progress: { label: 'In Progress', cls: 'status-in_progress' },
  resolved:    { label: 'Resolved',    cls: 'status-resolved' },
  closed:      { label: 'Closed',      cls: 'status-closed' },
  new:         { label: 'New',         cls: 'status-open' },
  investigating:{ label: 'Investigating', cls: 'status-in_progress' },
  contained:   { label: 'Contained',   cls: 'status-in_progress' },
  eradicated:  { label: 'Eradicated',  cls: 'status-resolved' },
  recovered:   { label: 'Recovered',   cls: 'status-resolved' },
};

export function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  return (
    <span className={cfg.cls}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot} mr-1`} />
      {cfg.label}
    </span>
  );
}

export function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || { label: status, cls: 'badge-info' };
  return <span className={cfg.cls}>{cfg.label}</span>;
}

export default SeverityBadge;
