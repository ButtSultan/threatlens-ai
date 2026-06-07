import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldCheckIcon } from '@heroicons/react/24/outline';
import api from '../utils/api';
import toast from 'react-hot-toast';
import { Spinner } from '../components/common/Loaders';

export default function RegisterPage() {
  const [form, setForm] = useState({ username: '', email: '', password: '', full_name: '' });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await api.post('/auth/register', { ...form, role: 'analyst' });
      toast.success('Account created. Please log in.');
      navigate('/login');
    } catch (err) {
      const detail = err.response?.data?.detail;
      toast.error(Array.isArray(detail) ? detail[0]?.msg || 'Registration failed' : detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const set = (field) => (e) => setForm(f => ({ ...f, [field]: e.target.value }));

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4 relative overflow-hidden">
      <div className="absolute inset-0 opacity-5" style={{ backgroundImage: 'linear-gradient(#0ea5e9 1px, transparent 1px), linear-gradient(90deg, #0ea5e9 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

      <div className="relative w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-cyber-600/20 border border-cyber-600/40 rounded-2xl mb-4">
            <ShieldCheckIcon className="w-8 h-8 text-cyber-400" />
          </div>
          <h1 className="text-3xl font-bold text-slate-100 font-display">ThreatLens AI</h1>
          <p className="text-slate-400 text-sm mt-1">Create Analyst Account</p>
        </div>

        <div className="card p-8">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Username *</label>
                <input className="input" placeholder="analyst01" value={form.username} onChange={set('username')} required />
              </div>
              <div>
                <label className="label">Full Name</label>
                <input className="input" placeholder="John Doe" value={form.full_name} onChange={set('full_name')} />
              </div>
            </div>
            <div>
              <label className="label">Email *</label>
              <input type="email" className="input" placeholder="analyst@soc.com" value={form.email} onChange={set('email')} required />
            </div>
            <div>
              <label className="label">Password *</label>
              <input type="password" className="input" placeholder="Min 8 chars, upper+lower+digit" value={form.password} onChange={set('password')} required />
              <p className="text-xs text-slate-500 mt-1">Must contain uppercase, lowercase, and a number.</p>
            </div>
            <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5">
              {loading ? <><Spinner size="sm" /> Creating account...</> : 'Create Analyst Account'}
            </button>
          </form>

          <p className="text-center text-sm text-slate-500 mt-6">
            Already have access?{' '}
            <Link to="/login" className="text-cyber-400 hover:text-cyber-300 font-medium">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
