import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  ArrowUpTrayIcon, DocumentTextIcon, ArrowPathIcon,
  CheckCircleIcon, ExclamationCircleIcon,
} from '@heroicons/react/24/outline';
import api from '../utils/api';
import Pagination from '../components/common/Pagination';
import EmptyState from '../components/common/EmptyState';
import { SkeletonRow } from '../components/common/Loaders';
import { format } from 'date-fns';
import toast from 'react-hot-toast';

export default function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef();

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/logs/', { params: { page, page_size: 50 } });
      setLogs(data.items);
      setTotal(data.total);
      setPages(data.pages);
    } catch {
      toast.error('Failed to load logs');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const uploadFile = async (file) => {
    if (!file) return;
    const allowed = ['json', 'csv', 'txt'];
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (!allowed.includes(ext)) {
      toast.error('Only JSON, CSV, and TXT files are supported');
      return;
    }
    setUploading(true);
    setResult(null);
    try {
      const form = new FormData();
      form.append('file', file);
      const { data } = await api.post('/logs/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setResult(data);
      toast.success(data.message);
      fetchLogs();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) uploadFile(file);
  };

  return (
    <div>
      <div className="page-header flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Log Ingestion</h1>
          <p className="page-subtitle">{total.toLocaleString()} logs stored</p>
        </div>
        <button onClick={fetchLogs} className="btn-secondary">
          <ArrowPathIcon className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Upload Zone */}
      <div
        className={`card mb-4 border-2 border-dashed transition-all duration-200 cursor-pointer ${
          dragOver
            ? 'border-cyber-500 bg-cyber-500/10'
            : 'border-slate-700 hover:border-slate-600'
        }`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => !uploading && fileRef.current?.click()}
      >
        <div className="flex flex-col items-center justify-center py-10 gap-3">
          <div className={`w-14 h-14 rounded-xl border flex items-center justify-center transition-colors ${
            dragOver ? 'bg-cyber-500/20 border-cyber-500/40' : 'bg-slate-800 border-slate-700'
          }`}>
            {uploading
              ? <div className="w-6 h-6 border-2 border-slate-600 border-t-cyber-500 rounded-full animate-spin" />
              : <ArrowUpTrayIcon className="w-7 h-7 text-slate-400" />
            }
          </div>
          <div className="text-center">
            <p className="text-sm font-medium text-slate-300">
              {uploading ? 'Analyzing logs...' : 'Drop log file here or click to browse'}
            </p>
            <p className="text-xs text-slate-500 mt-1">Supports JSON, CSV, TXT · Max 50MB</p>
          </div>
        </div>
        <input
          ref={fileRef}
          type="file"
          accept=".json,.csv,.txt"
          className="hidden"
          onChange={e => uploadFile(e.target.files?.[0])}
        />
      </div>

      {/* Upload Result Banner */}
      {result && (
        <div className="card p-4 mb-4 border border-green-500/30 bg-green-500/10">
          <div className="flex items-start gap-3">
            <CheckCircleIcon className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-semibold text-green-400 mb-2">Ingestion Complete — Batch: {result.batch_id}</p>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: 'Logs Processed', val: result.logs_processed },
                  { label: 'Logs Stored', val: result.logs_stored },
                  { label: 'Threats Detected', val: result.detections_created },
                  { label: 'Alerts Created', val: result.alerts_created },
                ].map(({ label, val }) => (
                  <div key={label} className="bg-slate-800/50 rounded-lg p-2 text-center">
                    <p className="text-xl font-bold text-slate-100">{val}</p>
                    <p className="text-xs text-slate-400">{label}</p>
                  </div>
                ))}
              </div>
            </div>
            <button onClick={() => setResult(null)} className="text-slate-400 hover:text-slate-200 text-lg leading-none">×</button>
          </div>
        </div>
      )}

      {/* Logs Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <table className="table"><thead><tr>
            {['Source File', 'Type', 'Source IP', 'Username', 'Event Type', 'Timestamp'].map(h => <th key={h}>{h}</th>)}
          </tr></thead><tbody>
            {Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} cols={6} />)}
          </tbody></table>
        ) : logs.length === 0 ? (
          <EmptyState
            icon={DocumentTextIcon}
            title="No logs ingested yet"
            description="Upload a JSON, CSV, or TXT log file above to start analysis."
          />
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Source File</th>
                  <th>Type</th>
                  <th>Source IP</th>
                  <th>Username</th>
                  <th>Event Type</th>
                  <th>Ingested</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id}>
                    <td>
                      <span className="text-xs font-mono text-slate-300 truncate block max-w-40">
                        {log.source_file || '—'}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs font-mono uppercase text-cyber-400 bg-cyber-400/10 px-2 py-0.5 rounded">
                        {log.log_type}
                      </span>
                    </td>
                    <td><span className="text-xs font-mono text-slate-300">{log.source_ip || '—'}</span></td>
                    <td><span className="text-xs text-slate-300">{log.username || '—'}</span></td>
                    <td><span className="text-xs text-slate-400">{log.event_type || '—'}</span></td>
                    <td>
                      <span className="text-xs font-mono text-slate-500">
                        {format(new Date(log.created_at), 'MM/dd HH:mm:ss')}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pagination page={page} pages={pages} total={total} pageSize={50} onPageChange={setPage} />
      </div>
    </div>
  );
}
