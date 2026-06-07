import React, { useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import {
  HomeIcon, BellAlertIcon, DocumentTextIcon,
  ExclamationTriangleIcon, ClipboardDocumentListIcon,
  MagnifyingGlassIcon, UsersIcon, ArrowLeftOnRectangleIcon,
  Bars3Icon,  ShieldCheckIcon,
  ChevronDoubleLeftIcon,
} from '@heroicons/react/24/outline';
import useAuthStore from '../../store/authStore';
import toast from 'react-hot-toast';

const NAV_ITEMS = [
  { to: '/',          label: 'Dashboard',  icon: HomeIcon,                    exact: true },
  { to: '/alerts',   label: 'Alerts',     icon: BellAlertIcon },
  { to: '/logs',     label: 'Logs',       icon: DocumentTextIcon },
  { to: '/incidents',label: 'Incidents',  icon: ExclamationTriangleIcon },
  { to: '/reports',  label: 'Reports',    icon: ClipboardDocumentListIcon },
  { to: '/search',   label: 'Search',     icon: MagnifyingGlassIcon },
];

const ADMIN_ITEMS = [
  { to: '/users', label: 'Users', icon: UsersIcon },
];

export default function AppLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    toast.success('Logged out successfully');
    navigate('/login');
  };

  const sidebarWidth = collapsed ? 'w-16' : 'w-60';

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className={`flex items-center gap-3 px-4 py-5 border-b border-slate-800 ${collapsed ? 'justify-center' : ''}`}>
        <div className="flex-shrink-0 w-8 h-8 bg-cyber-600 rounded-lg flex items-center justify-center">
          <ShieldCheckIcon className="w-5 h-5 text-white" />
        </div>
        {!collapsed && (
          <div>
            <p className="text-sm font-bold text-slate-100 font-display tracking-wide">ThreatLens</p>
            <p className="text-xs text-cyber-400">AI SOC Platform</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {!collapsed && (
          <p className="px-3 mb-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">Operations</p>
        )}
        {NAV_ITEMS.map(({ to, label, icon: Icon, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            className={({ isActive }) =>
              `sidebar-link ${isActive ? 'active' : ''} ${collapsed ? 'justify-center' : ''}`
            }
            title={collapsed ? label : undefined}
          >
            <Icon className="w-5 h-5 flex-shrink-0" />
            {!collapsed && <span>{label}</span>}
          </NavLink>
        ))}

        {user?.role === 'admin' && (
          <>
            {!collapsed && (
              <p className="px-3 mt-4 mb-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">Admin</p>
            )}
            {ADMIN_ITEMS.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `sidebar-link ${isActive ? 'active' : ''} ${collapsed ? 'justify-center' : ''}`
                }
                title={collapsed ? label : undefined}
              >
                <Icon className="w-5 h-5 flex-shrink-0" />
                {!collapsed && <span>{label}</span>}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      {/* User footer */}
      <div className="border-t border-slate-800 p-3">
        {!collapsed ? (
          <div className="flex items-center gap-3 mb-3 px-1">
            <div className="w-8 h-8 rounded-full bg-cyber-600/30 border border-cyber-600/50 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-bold text-cyber-400">
                {user?.username?.[0]?.toUpperCase() || 'U'}
              </span>
            </div>
            <div className="overflow-hidden">
              <p className="text-sm font-medium text-slate-200 truncate">{user?.username}</p>
              <p className="text-xs text-slate-500 capitalize">{user?.role}</p>
            </div>
          </div>
        ) : (
          <div className="flex justify-center mb-3">
            <div className="w-8 h-8 rounded-full bg-cyber-600/30 border border-cyber-600/50 flex items-center justify-center">
              <span className="text-xs font-bold text-cyber-400">
                {user?.username?.[0]?.toUpperCase() || 'U'}
              </span>
            </div>
          </div>
        )}
        <button
          onClick={handleLogout}
          className={`sidebar-link w-full text-red-400 hover:text-red-300 hover:bg-red-500/10 ${collapsed ? 'justify-center' : ''}`}
          title={collapsed ? 'Logout' : undefined}
        >
          <ArrowLeftOnRectangleIcon className="w-5 h-5 flex-shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>
    </div>
  );

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">
      {/* Desktop Sidebar */}
      <aside className={`hidden lg:flex flex-col ${sidebarWidth} bg-slate-900 border-r border-slate-800 transition-all duration-300 flex-shrink-0 relative`}>
        <SidebarContent />
        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="absolute -right-3 top-20 w-6 h-6 bg-slate-800 border border-slate-700 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-200 transition-colors z-10"
        >
          <ChevronDoubleLeftIcon className={`w-3 h-3 transition-transform duration-300 ${collapsed ? 'rotate-180' : ''}`} />
        </button>
      </aside>

      {/* Mobile sidebar overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
          <aside className="absolute left-0 top-0 bottom-0 w-60 bg-slate-900 border-r border-slate-800 z-50">
            <SidebarContent />
          </aside>
        </div>
      )}

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Topbar */}
        <header className="flex items-center justify-between px-4 lg:px-6 h-14 bg-slate-900/50 border-b border-slate-800 backdrop-blur-sm flex-shrink-0">
          <button
            onClick={() => setMobileOpen(true)}
            className="lg:hidden text-slate-400 hover:text-slate-200"
          >
            <Bars3Icon className="w-6 h-6" />
          </button>

          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-xs text-slate-400 font-mono hidden sm:block">SOC ACTIVE</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:block text-right">
              <p className="text-xs text-slate-500">Logged in as</p>
              <p className="text-sm font-medium text-slate-300">{user?.username}</p>
            </div>
            <div className="w-8 h-8 rounded-full bg-cyber-600/30 border border-cyber-600/50 flex items-center justify-center">
              <span className="text-xs font-bold text-cyber-400">
                {user?.username?.[0]?.toUpperCase()}
              </span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-6 animate-fade-in">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
