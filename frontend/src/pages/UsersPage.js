import React, { useEffect, useState, useCallback } from 'react';
import { UsersIcon, ArrowPathIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';
import api from '../utils/api';
import EmptyState from '../components/common/EmptyState';
import { SkeletonRow } from '../components/common/Loaders';
import { format, formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';

const ROLE_BADGE = {
  admin:   'bg-purple-500/20 text-purple-400 border border-purple-500/30',
  analyst: 'bg-cyber-500/20 text-cyber-400 border border-cyber-500/30',
  viewer:  'bg-slate-500/20 text-slate-400 border border-slate-500/30',
};

export default function UsersPage() {
  const [users, setUsers]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [togglingId, setTogglingId] = useState(null);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/users/');
      setUsers(data);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const toggleActive = async (user) => {
    setTogglingId(user.id);
    try {
      if (user.is_active) {
        await api.delete(`/users/${user.id}`);
        toast.success(`${user.username} deactivated`);
      } else {
        await api.patch(`/users/${user.id}`, {});
        toast.success(`${user.username} updated`);
      }
      fetchUsers();
    } catch {
      toast.error('Action failed');
    } finally {
      setTogglingId(null);
    }
  };

  return (
    <div>
      <div className="page-header flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">User Management</h1>
          <p className="page-subtitle">{users.length} registered users</p>
        </div>
        <button onClick={fetchUsers} className="btn-secondary">
          <ArrowPathIcon className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: 'Total Users', value: users.length, color: 'text-slate-200' },
          { label: 'Active',      value: users.filter(u => u.is_active).length, color: 'text-green-400' },
          { label: 'Admins',      value: users.filter(u => u.role === 'admin').length, color: 'text-purple-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card p-4 text-center">
            <p className={`text-2xl font-bold font-display ${color}`}>{value}</p>
            <p className="text-xs text-slate-500 mt-1">{label}</p>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <table className="table">
            <thead><tr>{['User', 'Role', 'Email', 'Status', 'Last Login', 'Joined', ''].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>{Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={7} />)}</tbody>
          </table>
        ) : users.length === 0 ? (
          <EmptyState icon={UsersIcon} title="No users found" description="No users are registered yet." />
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>Email</th>
                  <th>Status</th>
                  <th>Last Login</th>
                  <th>Joined</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-cyber-600/30 border border-cyber-600/50 flex items-center justify-center flex-shrink-0">
                          <span className="text-xs font-bold text-cyber-400">
                            {user.username[0].toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-slate-200">{user.username}</p>
                          {user.full_name && (
                            <p className="text-xs text-slate-500">{user.full_name}</p>
                          )}
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className={`text-xs font-semibold px-2.5 py-0.5 rounded-full ${ROLE_BADGE[user.role] || ROLE_BADGE.viewer}`}>
                        {user.role}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-400 font-mono">{user.email}</span>
                    </td>
                    <td>
                      <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${user.is_active ? 'text-green-400' : 'text-slate-500'}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${user.is_active ? 'bg-green-400' : 'bg-slate-500'}`} />
                        {user.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-500">
                        {user.last_login
                          ? formatDistanceToNow(new Date(user.last_login), { addSuffix: true })
                          : 'Never'}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs font-mono text-slate-500">
                        {format(new Date(user.created_at), 'MMM dd, yyyy')}
                      </span>
                    </td>
                    <td>
                      {user.role !== 'admin' && (
                        <button
                          onClick={() => toggleActive(user)}
                          disabled={togglingId === user.id}
                          className={`text-xs font-medium px-3 py-1 rounded-lg transition-colors ${
                            user.is_active
                              ? 'bg-red-500/10 text-red-400 hover:bg-red-500/20'
                              : 'bg-green-500/10 text-green-400 hover:bg-green-500/20'
                          } disabled:opacity-50`}
                        >
                          {togglingId === user.id ? '...' : user.is_active ? 'Deactivate' : 'Activate'}
                        </button>
                      )}
                      {user.role === 'admin' && (
                        <span className="flex items-center gap-1 text-xs text-purple-400">
                          <ShieldCheckIcon className="w-3.5 h-3.5" />
                          Protected
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
