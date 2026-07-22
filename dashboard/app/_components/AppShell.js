// Application shell: sidebar navigation, topbar, recording-mode chrome.
// The agents-online line derives from agentStatusInfo — the SAME source used by
// the Overview council tile, so the two counters can never disagree, and no
// fallback count is invented when the agent payload is missing.
import Link from "next/link";
import { useState } from "react";
import { NAV_ITEMS, agentStatusInfo, cx, navHref } from "./lib";
import { ConcordiaMark, Icon, Toast, useDelayedFlag, useRecordingMode, useUtcClock } from "./primitives";

export function AppShell({ view, data, children }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const recordingMode = useRecordingMode();
  const utc = useUtcClock();
  const agentStatus = agentStatusInfo(data.agents, data.loading);
  const connected = agentStatus.online > 0 || !data.baseError;
  const showConnectionIssue = useDelayedFlag(!connected, 10000);
  return <div className={cx("app-shell", recordingMode && "recording-mode", sidebarCollapsed && "sidebar-collapsed")}>
    <aside className={cx("sidebar", mobileOpen && "sidebar-open")} aria-hidden={recordingMode ? "true" : undefined}>
      <div className="sidebar-top">
        <ConcordiaMark compact={sidebarCollapsed} />
        <div className="sidebar-controls">
          <button
            className="sidebar-collapse"
            type="button"
            onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-pressed={sidebarCollapsed}
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <Icon name={sidebarCollapsed ? "chevronRight" : "chevronLeft"} />
          </button>
          <button className="sidebar-close" type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><Icon name="close" /></button>
        </div>
      </div>
      <nav className="nav-list" aria-label="Primary navigation">{NAV_ITEMS.map((item) => <Link key={item.id} className={cx("nav-item", view === item.id && "active")} href={navHref(item.href, data.selectedId)} onClick={() => setMobileOpen(false)}><Icon name={item.icon} size={20} /><span>{item.label}</span>{view === item.id && <span className="nav-active-marker" />}</Link>)}</nav>
      <div className="sidebar-footer"><div className="system-card"><div className="system-card-heading">System status</div><div className="system-status-line"><span className={cx("status-dot", connected ? "online" : "reconnecting")} />{connected ? "All systems operational" : showConnectionIssue ? "Reconnecting..." : "Checking connection..."}</div><div className="system-card-meta">{agentStatus.text}</div></div><div className="sidebar-version">Concordia DAO Council · Casper edition</div></div>
    </aside>
    <div className="app-main"><header className="topbar"><div className="topbar-left"><button className="mobile-menu" type="button" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Icon name="menu" /></button><div className="environment-switcher" aria-label="Selected reviewer scenario"><Icon name="shield" size={17} /><span>DAO Treasury Demo</span></div></div><div className="topbar-right"><div className={cx("room-status", connected ? "connected" : "disconnected")}><span className={cx("status-dot", connected ? "online" : "reconnecting")} />Council mesh {connected ? "Connected" : showConnectionIssue ? "Reconnecting..." : "Checking..."}</div><div className="utc-clock">{utc}</div><div className="topbar-user"><span>CD</span></div></div></header><main className="page-content">{children}</main></div>
    <Toast toast={data.toast} onClose={() => data.setToast(null)} />
  </div>;
}
