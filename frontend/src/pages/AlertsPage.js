import React, { useEffect, useState, useCallback } from 'react';
import {
  BellAlertIcon, FunnelIcon, ArrowPathIcon,
  CheckCircleIcon, ClockIcon, XCircleIcon,
} from '@heroicons/react/24/outline';
import api from '../utils/api';
import { SeverityBadge, StatusBadge } from '../components/common/SeverityBadge';
import Modal from '../components/common/Modal';
import Pagination from '../components/common/Pagination';
import EmptyState from '../components/common/EmptyState';
import { PageLoader, SkeletonRow } from '../components/common/Loaders';
import { formatDistanceToNow, format } from 'date-fns';
import toast from 'react-hot-toast';

const SEVERITY_OPTIONS = ['', 'critical', 'high', 'medium', 'low', 'info'];
const STATUS_OPTIONS   = ['', 'open', 'in_progress', 'resolved', 'closed'];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ severity: '', status: '' });
  const [selected, setSelected] = useState(null);
  const [updating, setUpdating] = useState(false);
  const [notes, setNotes] = useState('');
  const [newStatus, setNewStatus] = useState('');

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, page_size: 20 };
      if (filters.severity) params.severity = filters.severity;
      if (filters.status) params.status = filters.status;
      const { data } = await api.get('/alerts/', { params });
      setAlerts(data.items);
      setTotal(data.total);
      setPages(data.pages);
    } catch {
      toast.error('Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, [page, filters]);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

  const openDetail = (alert) => {
    setSelected(alert);
    setNotes(alert.analyst_notes || '');
    setNewStatus(alert.status);
  };

  const handleUpdate = async () => {
    if (!selected) return;
    setUpdating(true);
    try {
      await api.patch(`/alerts/${selected.id}`, {
        status: newStatus,
        analyst_notes: notes,
      });
      toast.success('Alert updated');
      setSelected(null);
      fetchAlerts();
    } catch {
      toast.error('Update failed');
    } finally {
      setUpdating(false);
    }
  };

  const quickStatus = async (id, status) => {
    try {
      await api.patch(`/alerts/${id}`, { status });
      toast.success(`Alert marked as ${status}`);
      fetchAlerts();
    } catch {
      toast.error('Update failed');
    }
  };

  const setFilter = (k) => (e) => {
    setFilters(f => ({ ...f, [k]: e.target.value }));
    setPage(1);
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Alert Management</h1>
          <p className="page-subtitle">{total} total alerts</p>
        </div>
        <button onClick={fetchAlerts} className="btn-secondary">
          <ArrowPathIcon className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="card p-4 mb-4 flex flex-wrap items-center gap-3">
        <FunnelIcon className="w-4 h-4 text-slate-400 flex-shrink-0" />
        <select className="input w-auto" value={filters.severity} onChange={setFilter('severity')}>
          <option value="">All Severities</option>
          {SEVERITY_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select className="input w-auto" value={filters.status} onChange={setFilter('status')}>
          <option value="">All Statuses</option>
          {STATUS_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}</option>
          ))}
        </select>
        {(filters.severity || filters.status) && (
          <button
            onClick={() => { setFilters({ severity: '', status: '' }); setPage(1); }}
            className="text-xs text-slate-400 hover:text-slate-200 underline"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <table className="table">
            <thead>
              <tr>
                {['Title', 'Severity', 'Status', 'Created', 'Actions'].map(h => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={5} />)}
            </tbody>
          </table>
        ) : alerts.length === 0 ? (
          <EmptyState
            icon={BellAlertIcon}
            title="No alerts found"
            description="Upload security logs to start detecting threats and generating alerts."
          />
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>AI Summary</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(alert => (
                  <tr key={alert.id}>
                    <td>
                      <button
                        onClick={() => openDetail(alert)}
                        className="text-slate-200 hover:text-cyber-400 font-medium text-left transition-colors"
                      >
                        {alert.title}
                      </button>
                    </td>
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td><StatusBadge status={alert.status} /></td>
                    <td>
                      <p className="text-xs text-slate-400 truncate max-w-48">
                        {alert.ai_summary || '—'}
                      </p>
                    </td>
                    <td>
                      <span className="text-xs text-slate-400 font-mono">
                        {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        {alert.status === 'open' && (
                          <>
                            <button
                              onClick={() => quickStatus(alert.id, 'in_progress')}
                              title="Mark In Progress"
                              className="p-1.5 text-yellow-400 hover:bg-yellow-400/10 rounded-lg transition-colors"
                            >
                              <ClockIcon className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => quickStatus(alert.id, 'resolved')}
                              title="Mark Resolved"
                              className="p-1.5 text-green-400 hover:bg-green-400/10 rounded-lg transition-colors"
                            >
                              <CheckCircleIcon className="w-4 h-4" />
                            </button>
                          </>
                        )}
                        {alert.status !== 'closed' && (
                          <button
                            onClick={() => quickStatus(alert.id, 'closed')}
                            title="Close Alert"
                            className="p-1.5 text-slate-400 hover:bg-slate-700 rounded-lg transition-colors"
                          >
                            <XCircleIcon className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pagination page={page} pages={pages} total={total} pageSize={20} onPageChange={setPage} />
      </div>

      {/* Alert Detail Modal */}
      <Modal isOpen={!!selected} onClose={() => setSelected(null)} title="Alert Details" size="xl">
        {selected && (
          <div className="space-y-5">
            {/* Header info */}
            <div className="flex items-start gap-4 p-4 bg-slate-800/50 rounded-xl border border-slate-700">
              <div className="flex-1">
                <h3 className="text-base font-semibold text-slate-100 mb-2">{selected.title}</h3>
                <div className="flex flex-wrap gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <StatusBadge status={selected.status} />
                  {selected.false_positive && (
                    <span className="badge-info">False Positive</span>
                  )}
                </div>
              </div>
              <div className="text-xs text-slate-500 font-mono text-right">
                <p>{format(new Date(selected.created_at), 'MMM dd, yyyy')}</p>
                <p>{format(new Date(selected.created_at), 'HH:mm:ss')}</p>
              </div>
            </div>

            {/* Description */}
            <div>
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Description</p>
              <p className="text-sm text-slate-300 leading-relaxed">{selected.description}</p>
            </div>

            {/* AI Summary */}
            {selected.ai_summary && (
              <div className="p-4 bg-cyber-600/10 border border-cyber-600/20 rounded-xl">
                <p className="text-xs font-semibold text-cyber-400 uppercase tracking-wider mb-2">🤖 AI Analysis</p>
                <p className="text-sm text-slate-300">{selected.ai_summary}</p>
              </div>
            )}

            {/* AI Recommendations */}
            {selected.ai_recommendations?.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Recommended Actions</p>
                <ol className="space-y-1.5">
                  {selected.ai_recommendations.map((rec, i) => (
                    <li key={i} className="flex gap-2 text-sm text-slate-300">
                      <span className="text-cyber-400 font-bold flex-shrink-0">{i + 1}.</span>
                      {rec}
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {/* MITRE */}
            {selected.detection?.mitre_mappings?.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">MITRE ATT&CK Techniques</p>
                <div className="flex flex-wrap gap-2">
                  {selected.detection.mitre_mappings.map(m => (
                    <div key={m.id} className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg">
                      <span className="text-xs font-mono text-cyber-400 font-bold">{m.technique_id}</span>
                      <span className="text-xs text-slate-300">{m.technique_name}</span>
                      <span className="text-xs text-slate-500">· {m.tactic}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Update form */}
            <div className="border-t border-slate-800 pt-4 space-y-3">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Update Alert</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">Status</label>
                  <select className="input" value={newStatus} onChange={e => setNewStatus(e.target.value)}>
                    {STATUS_OPTIONS.filter(Boolean).map(s => (
                      <option key={s} value={s}>{s.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <label className="label">Analyst Notes</label>
                <textarea
                  className="input resize-none"
                  rows={3}
                  placeholder="Add investigation notes..."
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                />
              </div>
              <div className="flex gap-3 justify-end">
                <button onClick={() => setSelected(null)} className="btn-secondary">Cancel</button>
                <button onClick={handleUpdate} disabled={updating} className="btn-primary">
                  {updating ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
