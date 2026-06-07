import React, { useEffect, useState, useCallback } from 'react';
import {
  ExclamationTriangleIcon, PlusIcon, ArrowPathIcon, PencilSquareIcon,
} from '@heroicons/react/24/outline';
import api from '../utils/api';
import { SeverityBadge, StatusBadge } from '../components/common/SeverityBadge';
import Modal from '../components/common/Modal';
import Pagination from '../components/common/Pagination';
import EmptyState from '../components/common/EmptyState';
import { SkeletonRow } from '../components/common/Loaders';
import { format, formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';

const SEVERITY_OPTS = ['critical', 'high', 'medium', 'low', 'info'];
const STATUS_OPTS = ['new', 'investigating', 'contained', 'eradicated', 'recovered', 'closed'];

const BLANK_CREATE = { title: '', description: '', severity: 'high', affected_assets: '' };
const BLANK_UPDATE = { status: '', root_cause: '', lessons_learned: '', containment_actions: '' };

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal]         = useState(0);
  const [pages, setPages]         = useState(1);
  const [page, setPage]           = useState(1);
  const [loading, setLoading]     = useState(true);
  const [filterStatus, setFilterStatus] = useState('');
  const [filterSev, setFilterSev] = useState('');

  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState(BLANK_CREATE);
  const [creating, setCreating]     = useState(false);

  const [editTarget, setEditTarget] = useState(null);
  const [editForm, setEditForm]     = useState(BLANK_UPDATE);
  const [editing, setEditing]       = useState(false);

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, page_size: 20 };
      if (filterStatus) params.status = filterStatus;
      if (filterSev) params.severity = filterSev;
      const { data } = await api.get('/incidents/', { params });
      setIncidents(data.items);
      setTotal(data.total);
      setPages(data.pages);
    } catch {
      toast.error('Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, [page, filterStatus, filterSev]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  /* ── Create ─────────────────────────────────────── */
  const handleCreate = async (e) => {
    e.preventDefault();
    if (!createForm.title.trim() || !createForm.description.trim()) {
      toast.error('Title and description are required');
      return;
    }
    setCreating(true);
    try {
      await api.post('/incidents/', {
        title: createForm.title,
        description: createForm.description,
        severity: createForm.severity,
        affected_assets: createForm.affected_assets
          ? createForm.affected_assets.split(',').map(s => s.trim()).filter(Boolean)
          : [],
      });
      toast.success('Incident created');
      setCreateOpen(false);
      setCreateForm(BLANK_CREATE);
      fetchIncidents();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Create failed');
    } finally {
      setCreating(false);
    }
  };

  /* ── Edit ───────────────────────────────────────── */
  const openEdit = (inc) => {
    setEditTarget(inc);
    setEditForm({
      status: inc.status,
      root_cause: inc.root_cause || '',
      lessons_learned: inc.lessons_learned || '',
      containment_actions: Array.isArray(inc.containment_actions)
        ? inc.containment_actions.join(', ')
        : '',
    });
  };

  const handleUpdate = async () => {
    if (!editTarget) return;
    setEditing(true);
    try {
      const payload = {
        status: editForm.status || undefined,
        root_cause: editForm.root_cause || undefined,
        lessons_learned: editForm.lessons_learned || undefined,
        containment_actions: editForm.containment_actions
          ? editForm.containment_actions.split(',').map(s => s.trim()).filter(Boolean)
          : undefined,
      };
      await api.patch(`/incidents/${editTarget.id}`, payload);
      toast.success('Incident updated');
      setEditTarget(null);
      fetchIncidents();
    } catch {
      toast.error('Update failed');
    } finally {
      setEditing(false);
    }
  };

  /* ── Field helpers ──────────────────────────────── */
  const setC = (k) => (e) => setCreateForm(f => ({ ...f, [k]: e.target.value }));
  const setE = (k) => (e) => setEditForm(f => ({ ...f, [k]: e.target.value }));

  /* ── Status chip color ──────────────────────────── */
  const statusBgMap = {
    new:          'text-red-400 bg-red-400/10',
    investigating:'text-yellow-400 bg-yellow-400/10',
    contained:    'text-orange-400 bg-orange-400/10',
    eradicated:   'text-purple-400 bg-purple-400/10',
    recovered:    'text-cyan-400 bg-cyan-400/10',
    closed:       'text-slate-400 bg-slate-400/10',
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Incident Management</h1>
          <p className="page-subtitle">{total} incidents recorded</p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchIncidents} className="btn-secondary">
            <ArrowPathIcon className="w-4 h-4" />
          </button>
          <button onClick={() => setCreateOpen(true)} className="btn-primary">
            <PlusIcon className="w-4 h-4" />
            New Incident
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 mb-4 flex flex-wrap gap-3 items-center">
        <select className="input w-auto" value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(1); }}>
          <option value="">All Statuses</option>
          {STATUS_OPTS.map(s => <option key={s} value={s}>{s.replace(/\b\w/g, c => c.toUpperCase())}</option>)}
        </select>
        <select className="input w-auto" value={filterSev} onChange={e => { setFilterSev(e.target.value); setPage(1); }}>
          <option value="">All Severities</option>
          {SEVERITY_OPTS.map(s => <option key={s} value={s}>{s.replace(/\b\w/g, c => c.toUpperCase())}</option>)}
        </select>
        {(filterStatus || filterSev) && (
          <button onClick={() => { setFilterStatus(''); setFilterSev(''); setPage(1); }} className="text-xs text-slate-400 hover:text-slate-200 underline">Clear</button>
        )}
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <table className="table">
            <thead><tr>{['#', 'Title', 'Severity', 'Status', 'Assets', 'Created', ''].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>{Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={7} />)}</tbody>
          </table>
        ) : incidents.length === 0 ? (
          <EmptyState
            icon={ExclamationTriangleIcon}
            title="No incidents found"
            description="Create incidents to track and manage security events through their full lifecycle."
            action={
              <button onClick={() => setCreateOpen(true)} className="btn-primary">
                <PlusIcon className="w-4 h-4" /> Create First Incident
              </button>
            }
          />
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Incident #</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Affected Assets</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {incidents.map(inc => (
                  <tr key={inc.id}>
                    <td>
                      <span className="text-xs font-mono text-cyber-400">{inc.incident_number}</span>
                    </td>
                    <td>
                      <div>
                        <p className="text-sm font-medium text-slate-200">{inc.title}</p>
                        <p className="text-xs text-slate-500 truncate max-w-48 mt-0.5">{inc.description}</p>
                      </div>
                    </td>
                    <td><SeverityBadge severity={inc.severity} /></td>
                    <td>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${statusBgMap[inc.status] || 'text-slate-400 bg-slate-400/10'}`}>
                        {inc.status.replace(/\b\w/g, c => c.toUpperCase())}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-400">
                        {Array.isArray(inc.affected_assets) && inc.affected_assets.length > 0
                          ? inc.affected_assets.slice(0, 2).join(', ') + (inc.affected_assets.length > 2 ? ` +${inc.affected_assets.length - 2}` : '')
                          : '—'}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-500 font-mono">
                        {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={() => openEdit(inc)}
                        className="p-1.5 text-slate-400 hover:text-cyber-400 hover:bg-cyber-400/10 rounded-lg transition-colors"
                        title="Edit Incident"
                      >
                        <PencilSquareIcon className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pagination page={page} pages={pages} total={total} pageSize={20} onPageChange={setPage} />
      </div>

      {/* ── Create Modal ───────────────────────────────── */}
      <Modal isOpen={createOpen} onClose={() => setCreateOpen(false)} title="Create New Incident" size="md">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="label">Title *</label>
            <input className="input" placeholder="Ransomware infection on DESKTOP-01" value={createForm.title} onChange={setC('title')} required />
          </div>
          <div>
            <label className="label">Description *</label>
            <textarea className="input resize-none" rows={3} placeholder="Describe the incident..." value={createForm.description} onChange={setC('description')} required />
          </div>
          <div>
            <label className="label">Severity</label>
            <select className="input" value={createForm.severity} onChange={setC('severity')}>
              {SEVERITY_OPTS.map(s => <option key={s} value={s}>{s.replace(/\b\w/g, c => c.toUpperCase())}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Affected Assets <span className="text-slate-500 font-normal">(comma-separated)</span></label>
            <input className="input" placeholder="DESKTOP-01, 192.168.1.50, user@corp.com" value={createForm.affected_assets} onChange={setC('affected_assets')} />
          </div>
          <div className="flex gap-3 justify-end pt-2">
            <button type="button" onClick={() => setCreateOpen(false)} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={creating} className="btn-primary">
              {creating ? 'Creating...' : 'Create Incident'}
            </button>
          </div>
        </form>
      </Modal>

      {/* ── Edit Modal ─────────────────────────────────── */}
      <Modal isOpen={!!editTarget} onClose={() => setEditTarget(null)} title={`Update: ${editTarget?.incident_number}`} size="lg">
        {editTarget && (
          <div className="space-y-4">
            {/* Incident summary */}
            <div className="p-3 bg-slate-800/50 rounded-xl border border-slate-700">
              <p className="text-sm font-semibold text-slate-200 mb-1">{editTarget.title}</p>
              <div className="flex gap-2">
                <SeverityBadge severity={editTarget.severity} />
                <StatusBadge status={editTarget.status} />
              </div>
            </div>

            <div>
              <label className="label">Status</label>
              <select className="input" value={editForm.status} onChange={setE('status')}>
                {STATUS_OPTS.map(s => <option key={s} value={s}>{s.replace(/\b\w/g, c => c.toUpperCase())}</option>)}
              </select>
            </div>

            <div>
              <label className="label">Containment Actions <span className="text-slate-500 font-normal">(comma-separated)</span></label>
              <input className="input" placeholder="Isolated host, reset credentials, blocked IP..." value={editForm.containment_actions} onChange={setE('containment_actions')} />
            </div>

            <div>
              <label className="label">Root Cause Analysis</label>
              <textarea className="input resize-none" rows={3} placeholder="Describe the root cause..." value={editForm.root_cause} onChange={setE('root_cause')} />
            </div>

            <div>
              <label className="label">Lessons Learned</label>
              <textarea className="input resize-none" rows={3} placeholder="What can be improved?" value={editForm.lessons_learned} onChange={setE('lessons_learned')} />
            </div>

            <div className="flex gap-3 justify-end pt-2">
              <button onClick={() => setEditTarget(null)} className="btn-secondary">Cancel</button>
              <button onClick={handleUpdate} disabled={editing} className="btn-primary">
                {editing ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
