import React, { useEffect, useState, useCallback } from 'react';
import {
  BellAlertIcon, ShieldExclamationIcon, DocumentMagnifyingGlassIcon,
  ExclamationTriangleIcon, ServerStackIcon, ClockIcon,
  CheckCircleIcon, FireIcon,
} from '@heroicons/react/24/outline';
import api from '../utils/api';
import StatCard from '../components/dashboard/StatCard';
import { SeverityDonut, DetectionTrendChart, MITREBarChart } from '../components/dashboard/Charts';
import { SeverityBadge, StatusBadge } from '../components/common/SeverityBadge';
import { PageLoader, StatCardSkeleton } from '../components/common/Loaders';
import { formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchDashboard = useCallback(async () => {
    try {
      const { data: d } = await api.get('/dashboard/');
      setData(d);
    } catch {
      toast.error('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboard();
    // Auto-refresh every 60 seconds
    const interval = setInterval(fetchDashboard, 60000);
    return () => clearInterval(interval);
  }, [fetchDashboard]);

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Loading security analytics...</p>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {Array.from({ length: 8 }).map((_, i) => <StatCardSkeleton key={i} />)}
        </div>
        <PageLoader />
      </div>
    );
  }

  const stats = data?.stats || {};

  return (
    <div className="animate-fade-in">
      {/* Page Header */}
      <div className="page-header flex items-center justify-between">
        <div>
          <h1 className="page-title">SOC Dashboard</h1>
          <p className="page-subtitle">Real-time security operations overview</p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-green-400 bg-green-400/10 border border-green-400/20 px-3 py-1.5 rounded-full">
          <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          LIVE
        </div>
      </div>

      {/* Stat Cards Row 1 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
        <StatCard title="Total Logs" value={stats.total_logs?.toLocaleString()} icon={ServerStackIcon} color="slate" subtitle={`${stats.logs_today} today`} />
        <StatCard title="Total Alerts" value={stats.total_alerts?.toLocaleString()} icon={BellAlertIcon} color="cyber" subtitle={`${stats.open_alerts} open`} />
        <StatCard title="Critical Alerts" value={stats.critical_alerts} icon={FireIcon} color="red" />
        <StatCard title="High Alerts" value={stats.high_severity_alerts} icon={ShieldExclamationIcon} color="orange" />
      </div>

      {/* Stat Cards Row 2 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard title="Detections Today" value={stats.detections_today} icon={DocumentMagnifyingGlassIcon} color="purple" />
        <StatCard title="Open Alerts" value={stats.open_alerts} icon={ExclamationTriangleIcon} color="yellow" />
        <StatCard title="Active Incidents" value={stats.active_incidents} icon={ClockIcon} color="orange" />
        <StatCard title="Total Incidents" value={stats.total_incidents} icon={CheckCircleIcon} color="green" />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        {/* Severity Distribution */}
        <div className="card">
          <div className="card-header">
            <h3 className="text-sm font-semibold text-slate-200">Alert Severity Distribution</h3>
          </div>
          <div className="p-5">
            <SeverityDonut data={data?.severity_distribution} />
          </div>
        </div>

        {/* Detection Trends */}
        <div className="card lg:col-span-2">
          <div className="card-header">
            <h3 className="text-sm font-semibold text-slate-200">Detection Trends (Last 7 Days)</h3>
          </div>
          <div className="p-5">
            <DetectionTrendChart data={data?.detection_trends} />
          </div>
        </div>
      </div>

      {/* MITRE + Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* MITRE ATT&CK Distribution */}
        <div className="card">
          <div className="card-header">
            <h3 className="text-sm font-semibold text-slate-200">MITRE ATT&CK Tactic Distribution</h3>
          </div>
          <div className="p-5">
            <MITREBarChart data={data?.mitre_distribution} />
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="card flex flex-col">
          <div className="card-header">
            <h3 className="text-sm font-semibold text-slate-200">Recent Alerts</h3>
          </div>
          <div className="flex-1 overflow-y-auto divide-y divide-slate-800">
            {data?.recent_alerts?.length ? (
              data.recent_alerts.map(alert => (
                <div key={alert.id} className="px-4 py-3 hover:bg-slate-800/30 transition-colors">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <p className="text-sm text-slate-200 font-medium truncate flex-1">{alert.title}</p>
                    <SeverityBadge severity={alert.severity} />
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusBadge status={alert.status} />
                    <span className="text-xs text-slate-500">
                      {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="px-4 py-8 text-center text-sm text-slate-500">
                No alerts yet. Upload logs to start detection.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
