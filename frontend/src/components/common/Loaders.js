import React from 'react';

export function Spinner({ size = 'md', className = '' }) {
  const sizes = { sm: 'w-4 h-4', md: 'w-6 h-6', lg: 'w-8 h-8', xl: 'w-12 h-12' };
  return (
    <div className={`animate-spin rounded-full border-2 border-slate-700 border-t-cyber-500 ${sizes[size]} ${className}`} />
  );
}

export function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="flex flex-col items-center gap-3">
        <Spinner size="lg" />
        <p className="text-sm text-slate-400 font-mono animate-pulse">Analyzing...</p>
      </div>
    </div>
  );
}

export function SkeletonRow({ cols = 5 }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-slate-800 rounded animate-pulse" />
        </td>
      ))}
    </tr>
  );
}

export function StatCardSkeleton() {
  return (
    <div className="stat-card">
      <div className="h-4 w-24 bg-slate-800 rounded animate-pulse" />
      <div className="h-8 w-16 bg-slate-800 rounded animate-pulse" />
      <div className="h-3 w-32 bg-slate-800 rounded animate-pulse" />
    </div>
  );
}
