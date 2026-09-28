import { useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import {
  Bell,
  Boxes,
  ChevronDown,
  ChevronLeft,
  Command,
  GitBranch,
  Inbox,
  LayoutDashboard,
  ListFilter,
  Menu,
  Moon,
  RotateCcw,
  Search,
  Settings,
  ShieldCheck,
  Sun,
  Workflow,
  X,
} from "lucide-react";
import { StatusTag } from "../common/UI.jsx";

const navigation = [
  { label: "Overview", path: "/", icon: LayoutDashboard },
  { label: "Ingestion", path: "/ingestion", icon: Inbox },
  { label: "Pipeline", path: "/pipeline", icon: Workflow },
  { label: "Events", path: "/events", icon: ListFilter },
  { label: "Parsers", path: "/parsers", icon: Boxes },
  { label: "Provenance", path: "/provenance", icon: GitBranch },
  { label: "Replay", path: "/replay", icon: RotateCcw },
  { label: "Governance", path: "/governance", icon: ShieldCheck },
];

const pageNames = Object.fromEntries(navigation.map(({ label, path }) => [path, label]));

export default function AppShell({ children, darkMode, onToggleTheme }) {
  const [collapsed, setCollapsed] = useState(false);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const currentPath = location.pathname === "/settings" ? "/settings" : location.pathname;
  const pageName = pageNames[currentPath] ?? "Overview";

  function submitSearch(event) {
    event.preventDefault();
    navigate(`/events${search.trim() ? `?q=${encodeURIComponent(search.trim())}` : ""}`);
    setMobileNavOpen(false);
  }

  return (
    <div className={`app-frame${darkMode ? " theme-dark" : ""}${collapsed ? " sidebar-collapsed" : ""}`}>
      <aside className={`sidebar${mobileNavOpen ? " mobile-nav-open" : ""}`}>
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true"><span /><span /><span /></div>
          <div className="brand-copy"><strong>drishti</strong><span>CONTROL PLANE</span></div>
          <button className="mobile-close icon-button" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)}><X size={17} /></button>
        </div>

        <div className="workspace-switcher">
          <div className="workspace-avatar">N</div>
          <div className="workspace-copy"><strong>Northstar Labs</strong><span>Workspace</span></div>
          <ChevronDown size={14} />
        </div>

        <div className="sidebar-label">WORKSPACE</div>
        <nav className="primary-nav" aria-label="Main navigation">
          {navigation.map(({ label, path, icon: Icon }) => (
            <NavLink
              key={path}
              to={path}
              end={path === "/"}
              className={({ isActive }) => `nav-link${isActive ? " nav-active" : ""}`}
              onClick={() => setMobileNavOpen(false)}
              title={collapsed ? label : undefined}
            >
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-spacer" />
        <div className="sidebar-label sidebar-settings-label">PREFERENCES</div>
        <NavLink to="/settings" className={({ isActive }) => `nav-link${isActive ? " nav-active" : ""}`} title={collapsed ? "Settings" : undefined}>
          <Settings size={17} strokeWidth={1.8} /><span>Settings</span>
        </NavLink>

        <div className="sidebar-footer">
          <div className="sidebar-health"><StatusTag status="healthy">System operational</StatusTag></div>
          <div className="sidebar-footnote"><span>DRISHTI</span><span>v0.4.0</span></div>
          <button className="collapse-control" onClick={() => setCollapsed(!collapsed)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
            <ChevronLeft size={15} className={collapsed ? "rotate-180" : ""} /><span>Collapse sidebar</span>
          </button>
        </div>
      </aside>

      <div className="workspace-shell">
        <header className="topbar">
          <div className="topbar-leading">
            <button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Menu size={18} /></button>
            <div className="breadcrumb"><span>Workspace</span><span className="breadcrumb-divider">/</span><strong>{pageName}</strong></div>
          </div>
          <form className="global-search" onSubmit={submitSearch} role="search">
            <Search size={15} />
            <input aria-label="Search events" placeholder="Search events, sources…" value={search} onChange={(event) => setSearch(event.target.value)} />
            <kbd><Command size={11} /> K</kbd>
          </form>
          <div className="topbar-actions">
            <span className="api-live"><i /> Mock data</span>
            <div className="notice-wrap">
              <button className="icon-button notification-button" aria-label="Notifications" onClick={() => setNoticeOpen(!noticeOpen)}><Bell size={17} /><i /></button>
              {noticeOpen && <div className="notice-popover"><div className="notice-title">Recent updates</div><p><span className="notice-dot green" /> All pipeline components operational</p><p><span className="notice-dot amber" /> 1 parser awaiting review</p><button onClick={() => setNoticeOpen(false)}>Dismiss</button></div>}
            </div>
            <button className="icon-button theme-control" aria-label={darkMode ? "Switch to light theme" : "Switch to dark theme"} onClick={onToggleTheme}>{darkMode ? <Sun size={17} /> : <Moon size={17} />}</button>
            <span className="topbar-divider" />
            <button className="profile-button" aria-label="Open profile menu"><span className="profile-avatar">AM</span><ChevronDown size={13} /></button>
          </div>
        </header>

        <main className="main-content" key={location.pathname}>
          {children}
          <footer className="content-footer"><span>Preserve. Normalize. Trace.</span><span>All times UTC · Data shown is illustrative</span></footer>
        </main>
      </div>
      {mobileNavOpen && <button className="mobile-nav-backdrop" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
    </div>
  );
}