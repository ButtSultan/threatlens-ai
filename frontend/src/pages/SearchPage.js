import React, { useState, useCallback } from 'react';
import {
  MagnifyingGlassIcon, FunnelIcon, DocumentTextIcon,
  BellAlertIcon,
} from '@heroicons/react/24/outline';
import api from '../utils/api';
import { SeverityBadge, StatusBadge } from '../components/common/SeverityBadge';
import Pagination from '../components/common/Pagination';
import EmptyState from '../components/common/EmptyState';
import { SkeletonRow } from '../components/common/Loaders';
import { format } from 'date-fns';
import toast from 'react-hot-toast';

const TABS = [
  { key: 'alerts', label: 'Alerts', icon: BellAlertIcon },
  { key: 'logs',   label: 'Logs',   icon: DocumentTextIcon },
];

export default function SearchPage() {
  const [tab, setTab]         = useState('alerts');
  const [query, setQuery]     = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus]   = useState('');
  const [startDate, setStart] = useState('');
  const [endDate, setEnd]     = useState('');

  const [results, setResults] = useState([]);
  const [total, setTotal]     = useState(0);
  const [pages, setPages]     = useState(1);
  const [page, setPage]       = useState(1);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  const runSearch = useCallback(async (p = 1) => {
    setLoading(true);
    setSearched(true);
    try {
      const params = { page: p, page_size: 25 };
      if (query.trim()) params.q = query.trim();
      if (severity) params.severity = severity;
      if (status)   params.status   = status;
      if (startDate) params.start_date = new Date(startDate).toISOString();
      if (endDate)   params.end_date   = new Date(endDate).toISOString();

      const endpoint = tab === 'alerts' ? '/search/alerts' : '/search/logs';
      const { data } = await api.get(endpoint, { params });
      setResults(data.items);
      setTotal(data.total);
      setPages(data.pages);
      setPage(p);
    } catch {
      toast.error('Search failed');
    } finally {
      setLoading(false);
    }
  }, [tab, query, severity, status, startDate, endDate]);

  const handleSubmit = (e) => {
    e.preventDefault();
    runSearch(1);
  };

  const handleTabChange = (t) => {
    setTab(t);
    setResults([]);
    setSearched(false);
    setTotal(0);
    setSeverity('');
    setStatus('');
  };

  const clearFilters = () => {
    setQuery('');
    setSeverity('');
    setStatus('');
    setStart('');
    setEnd('');
    setResults([]);
    setSearched(false);
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Search</h1>
        <p className="page-subtitle">Search across all logs and alerts</p>
      </div>

      {/* Tab switcher */}
      <div className="flex gap-1 mb-4 p-1 bg-slate-900 border border-slate-800 rounded-xl w-fit">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => handleTabChange(key)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tab === key
                ? 'bg-cyber-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Search form */}
      <div className="card p-5 mb-4">
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Main search bar */}
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              className="input pl-9 text-base"
              placeholder={
                tab === 'alerts'
                  ? 'Search by title or description...'
                  : 'Search by IP, username, event type, hostname...'
              }
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
          </div>

          {/* Filters row */}
          <div className="flex flex-wrap gap-3 items-end">
            <div className="flex items-center gap-2 text-slate-400">
              <FunnelIcon className="w-4 h-4" />
              <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Filters</span>
            </div>

            {tab === 'alerts' && (
              <>
                <select className="input w-auto text-sm" value={severity} onChange={e => setSeverity(e.target.value)}>
                  <option value="">Any Severity</option>
                  {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                    <option key={s} value={s}>{s.replace(/\b\w/g, c => c.toUpperCase())}</option>
                  ))}
                </select>
                <select className="input w-auto text-sm" value={status} onChange={e => setStatus(e.target.value)}>
                  <option value="">Any Status</option>
                  {['open', 'in_progress', 'resolved', 'closed'].map(s => (
                    <option key={s} value={s}>{s.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}</option>
                  ))}
                </select>
              </>
            )}

            <div className="flex items-center gap-2">
              <input type="date" className="input w-auto text-sm" value={startDate} onChange={e => setStart(e.target.value)} title="Start Date" />
              <span className="text-slate-500 text-sm">→</span>
              <input type="date" className="input w-auto text-sm" value={endDate} onChange={e => setEnd(e.target.value)} title="End Date" />
            </div>

            <div className="flex gap-2 ml-auto">
              {(query || severity || status || startDate || endDate) && (
                <button type="button" onClick={clearFilters} className="btn-secondary text-sm">
                  Clear
                </button>
              )}
              <button type="submit" disabled={loading} className="btn-primary text-sm">
                {loading ? (
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <MagnifyingGlassIcon className="w-4 h-4" />
                )}
                Search
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Results */}
      {!searched ? (
        <div className="card">
          <EmptyState
            icon={MagnifyingGlassIcon}
            title="Enter a search query"
            description="Search across logs and alerts using keywords, IPs, usernames, or apply filters."
          />
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="card-header flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">
              {loading ? 'Searching...' : `${total.toLocaleString()} results found`}
            </h3>
            {total > 0 && !loading && (
              <span className="text-xs text-slate-500">Page {page} of {pages}</span>
            )}
          </div>

          {loading ? (
            <table className="table">
              <thead><tr>{Array.from({ length: 5 }).map((_, i) => <th key={i}>—</th>)}</tr></thead>
              <tbody>{Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={5} />)}</tbody>
            </table>
          ) : results.length === 0 ? (
            <EmptyState
              icon={MagnifyingGlassIcon}
              title="No results found"
              description="Try different keywords or adjust your filters."
            />
          ) : tab === 'alerts' ? (
            /* Alert results */
            <div className="table-wrapper">
              <table className="table">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>AI Summary</th>
                    <th>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map(alert => (
                    <tr key={alert.id}>
                      <td>
                        <p className="text-sm font-medium text-slate-200">{alert.title}</p>
                        <p className="text-xs text-slate-500 truncate max-w-64 mt-0.5">{alert.description}</p>
                      </td>
                      <td><SeverityBadge severity={alert.severity} /></td>
                      <td><StatusBadge status={alert.status} /></td>
                      <td>
                        <p className="text-xs text-slate-400 truncate max-w-48">
                          {alert.ai_summary || '—'}
                        </p>
                      </td>
                      <td>
                        <span className="text-xs font-mono text-slate-500">
                          {format(new Date(alert.created_at), 'MM/dd/yyyy HH:mm')}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            /* Log results */
            <div className="table-wrapper">
              <table className="table">
                <thead>
                  <tr>
                    <th>Source File</th>
                    <th>Source IP</th>
                    <th>Username</th>
                    <th>Event Type</th>
                    <th>Ingested</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map(log => (
                    <tr key={log.id}>
                      <td>
                        <span className="text-xs font-mono text-slate-300">{log.source_file || '—'}</span>
                      </td>
                      <td><span className="text-xs font-mono text-slate-300">{log.source_ip || '—'}</span></td>
                      <td><span className="text-xs text-slate-300">{log.username || '—'}</span></td>
                      <td><span className="text-xs text-slate-400">{log.event_type || '—'}</span></td>
                      <td>
                        <span className="text-xs font-mono text-slate-500">
                          {format(new Date(log.created_at), 'MM/dd/yyyy HH:mm')}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <Pagination
            page={page}
            pages={pages}
            total={total}
            pageSize={25}
            onPageChange={(p) => { setPage(p); runSearch(p); }}
          />
        </div>
      )}
    </div>
  );
}
