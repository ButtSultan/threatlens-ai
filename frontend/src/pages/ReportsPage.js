import React, { useEffect, useState, useCallback } from 'react';
import {
  ClipboardDocumentListIcon, DocumentArrowDownIcon,
  PlusIcon, ArrowPathIcon, SparklesIcon,
} from '@heroicons/react/24/outline';
import api from '../utils/api';
import Modal from '../components/common/Modal';
import EmptyState from '../components/common/EmptyState';
import { SkeletonRow } from '../components/common/Loaders';
import { format } from 'date-fns';
import toast from 'react-hot-toast';

const REPORT_TYPES = [
  { value: 'incident', label: 'Incident Report', description: 'Detailed report for a specific security incident' },
  { value: 'executive', label: 'Executive Summary', description: 'High-level security posture overview for leadership' },
  { value: 'summary', label: 'Threat Summary', description: 'Overview of all detected threats and alerts' },
];

export default function ReportsPage() {
  const [reports, setReports]     = useState([]);
  const [loading, setLoading]     = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [generating, setGenerating] = useState(false);

  const [form, setForm] = useState({
    title: '',
    report_type: 'executive',
    incident_id: '',
  });

  const fetchReports = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/reports/');
      setReports(data);
    } catch {
      toast.error('Failed to load reports');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchIncidents = useCallback(async () => {
    try {
      const { data } = await api.get('/incidents/', { params: { page: 1, page_size: 100 } });
      setIncidents(data.items);
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    fetchReports();
    fetchIncidents();
  }, [fetchReports, fetchIncidents]);

  const handleGenerate = async (e) => {
    e.preventDefault();
    if (!form.title.trim()) { toast.error('Report title is required'); return; }
    if (form.report_type === 'incident' && !form.incident_id) {
      toast.error('Please select an incident for an incident report');
      return;
    }
    setGenerating(true);
    try {
      const payload = {
        title: form.title,
        report_type: form.report_type,
        incident_id: form.report_type === 'incident' ? form.incident_id : undefined,
      };
      const { data } = await api.post('/reports/generate', payload);
      toast.success('Report generated successfully');
      setCreateOpen(false);
      setForm({ title: '', report_type: 'executive', incident_id: '' });
      fetchReports();
      // Auto-download
      handleDownload(data.id, data.title);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Report generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (id, title) => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(
        `${process.env.REACT_APP_API_URL || '/api/v1'}/reports/${id}/download`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!response.ok) throw new Error('Download failed');
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${title.replace(/\s+/g, '_')}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success('Report downloaded');
    } catch {
      toast.error('Download failed');
    }
  };

  const setF = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));

  const typeIcon = (type) => {
    const icons = { incident: '🔴', executive: '📊', summary: '🛡️' };
    return icons[type] || '📄';
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">Generate and download PDF security reports</p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchReports} className="btn-secondary">
            <ArrowPathIcon className="w-4 h-4" />
          </button>
          <button onClick={() => setCreateOpen(true)} className="btn-primary">
            <PlusIcon className="w-4 h-4" />
            Generate Report
          </button>
        </div>
      </div>

      {/* Report type cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        {REPORT_TYPES.map(rt => (
          <div key={rt.value} className="card p-5 hover:border-slate-700 transition-colors cursor-pointer group" onClick={() => { setForm(f => ({ ...f, report_type: rt.value, title: rt.label })); setCreateOpen(true); }}>
            <div className="text-3xl mb-3">{typeIcon(rt.value)}</div>
            <p className="text-sm font-semibold text-slate-200 mb-1 group-hover:text-cyber-400 transition-colors">{rt.label}</p>
            <p className="text-xs text-slate-500">{rt.description}</p>
          </div>
        ))}
      </div>

      {/* Reports list */}
      <div className="card overflow-hidden">
        <div className="card-header">
          <h3 className="text-sm font-semibold text-slate-200">Generated Reports</h3>
        </div>

        {loading ? (
          <table className="table">
            <thead><tr>{['Title', 'Type', 'Generated', ''].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>{Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={4} />)}</tbody>
          </table>
        ) : reports.length === 0 ? (
          <EmptyState
            icon={ClipboardDocumentListIcon}
            title="No reports generated yet"
            description="Click 'Generate Report' to create your first PDF security report."
            action={
              <button onClick={() => setCreateOpen(true)} className="btn-primary">
                <SparklesIcon className="w-4 h-4" /> Generate First Report
              </button>
            }
          />
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Type</th>
                  <th>Generated</th>
                  <th className="text-right">Download</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(report => (
                  <tr key={report.id}>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{typeIcon(report.report_type)}</span>
                        <span className="text-sm font-medium text-slate-200">{report.title}</span>
                      </div>
                    </td>
                    <td>
                      <span className="text-xs font-mono uppercase text-cyber-400 bg-cyber-400/10 px-2 py-0.5 rounded">
                        {report.report_type}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-400 font-mono">
                        {format(new Date(report.created_at), 'MMM dd, yyyy · HH:mm')}
                      </span>
                    </td>
                    <td className="text-right">
                      <button
                        onClick={() => handleDownload(report.id, report.title)}
                        className="inline-flex items-center gap-1.5 text-xs text-cyber-400 hover:text-cyber-300 font-medium transition-colors"
                      >
                        <DocumentArrowDownIcon className="w-4 h-4" />
                        Download PDF
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Generate Modal */}
      <Modal isOpen={createOpen} onClose={() => setCreateOpen(false)} title="Generate Security Report" size="md">
        <form onSubmit={handleGenerate} className="space-y-4">
          <div>
            <label className="label">Report Type</label>
            <div className="grid grid-cols-1 gap-2">
              {REPORT_TYPES.map(rt => (
                <label
                  key={rt.value}
                  className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                    form.report_type === rt.value
                      ? 'border-cyber-500 bg-cyber-500/10'
                      : 'border-slate-700 hover:border-slate-600'
                  }`}
                >
                  <input
                    type="radio"
                    name="report_type"
                    value={rt.value}
                    checked={form.report_type === rt.value}
                    onChange={setF('report_type')}
                    className="mt-0.5 accent-cyber-500"
                  />
                  <div>
                    <p className="text-sm font-medium text-slate-200">{typeIcon(rt.value)} {rt.label}</p>
                    <p className="text-xs text-slate-500">{rt.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="label">Report Title *</label>
            <input className="input" placeholder="Q4 2024 Security Summary" value={form.title} onChange={setF('title')} required />
          </div>

          {form.report_type === 'incident' && (
            <div>
              <label className="label">Select Incident *</label>
              <select className="input" value={form.incident_id} onChange={setF('incident_id')}>
                <option value="">— Choose Incident —</option>
                {incidents.map(inc => (
                  <option key={inc.id} value={inc.id}>
                    {inc.incident_number} · {inc.title}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="flex gap-3 justify-end pt-2">
            <button type="button" onClick={() => setCreateOpen(false)} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={generating} className="btn-primary">
              {generating ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Generating...
                </>
              ) : (
                <><SparklesIcon className="w-4 h-4" />Generate PDF</>
              )}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
