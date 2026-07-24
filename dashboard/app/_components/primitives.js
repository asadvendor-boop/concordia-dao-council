// Presentational atoms and shared hooks. Prop-driven, no data fetching.
import Link from "next/link";
import { useEffect, useState } from "react";
import { cx, normalizeJudgeText, PROFILES, publicJson, shortHash } from "./lib";

export function Icon({ name, size = 20, className = "", strokeWidth = 1.8 }) {
  const paths = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    proposal: <><path d="M12 3 2.8 20h18.4L12 3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></>,
    approval: <><path d="M9 3h6l1 2h3v16H5V5h3l1-2Z"/><path d="m8.5 13 2.2 2.2 4.8-5"/></>,
    agents: <><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></>,
    evidence: <><path d="M6 2h9l4 4v16H6z"/><path d="M14 2v5h5"/><path d="M9 13h6M9 17h6M9 9h2"/></>,
    replay: <><circle cx="12" cy="12" r="9"/><path d="m10 8 6 4-6 4z"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.13-1.35l2-1.55-2-3.46-2.45 1A7 7 0 0 0 14 5.25L13.65 2h-4L9.3 5.25a7 7 0 0 0-2.42 1.4l-2.45-1-2 3.46 2 1.55A7 7 0 0 0 4.3 12c0 .46.04.9.13 1.35l-2 1.55 2 3.46 2.45-1a7 7 0 0 0 2.42 1.4l.35 3.24h4l.35-3.25a7 7 0 0 0 2.42-1.4l2.45 1 2-3.46-2-1.55c.09-.44.13-.89.13-1.35Z"/></>,
    shield: <><path d="M12 2 4 5v6c0 5 3.4 8.7 8 11 4.6-2.3 8-6 8-11V5z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></>,
    signal: <><path d="M12 3 2.8 20h18.4L12 3Z"/><path d="M12 9v4M12 17h.01"/></>,
    network: <><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="18" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="m10.8 7.1-4.6 8M13.2 7.1l4.6 8M7.5 18h9"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    activity: <path d="M3 12h4l2-5 4 10 2-5h6"/>,
    challenge: <><path d="M5 19 19 5M9 5l-4 4M15 19l4-4"/><path d="m14 4 6 6M4 14l6 6"/></>,
    human: <><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></>,
    check: <path d="m5 12 4 4L19 6"/>, close: <path d="M6 6l12 12M18 6 6 18"/>, chevronRight: <path d="m9 18 6-6-6-6"/>, chevronLeft: <path d="m15 18-6-6 6-6"/>, chevronDown: <path d="m6 9 6 6 6-6"/>, arrowRight: <path d="M5 12h14M13 6l6 6-6 6"/>,
    external: <><path d="M14 3h7v7"/><path d="M10 14 21 3"/><path d="M21 14v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h6"/></>,
    download: <><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></>,
    refresh: <><path d="M20 7h-5V2"/><path d="M4 17h5v5"/><path d="M5.5 7a8 8 0 0 1 13.4-2L20 7M4 17l1.1 2a8 8 0 0 0 13.4-2"/></>,
    play: <path d="m8 5 11 7-11 7z"/>, pause: <><path d="M8 5h3v14H8zM14 5h3v14h-3z"/></>, previous: <><path d="M6 5v14"/><path d="m18 6-8 6 8 6z"/></>, next: <><path d="M18 5v14"/><path d="m6 6 8 6-8 6z"/></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></>,
    link: <><path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.1-1.1"/></>,
    code: <><path d="m8 9-4 3 4 3M16 9l4 3-4 3M14 5l-4 14"/></>, copy: <><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/></>, menu: <path d="M4 7h16M4 12h16M4 17h16"/>, info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></>,
  };
  return <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.info}</svg>;
}

export function ConcordiaMark({ compact = false }) {
  return <div className={cx("brand", compact && "brand-compact")}><span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 48 54"><path d="M24 2 44 9v14c0 13-7.6 23-20 29C11.6 46 4 36 4 23V9L24 2Z"/><path d="m15 28 6 6 12-15"/><path d="M15 14h18"/></svg></span>{!compact && <span className="brand-copy"><strong>Concordia DAO Council</strong><small>agentic Casper governance chamber</small></span>}</div>;
}
export function Avatar({ profile, size = "md", status, className = "" }) {
  const person = profile || PROFILES.system;
  return <span className={cx("avatar", `avatar-${size}`, className)} style={{ "--avatar-accent": person.color }} title={`${person.name} — ${person.role}`}>{person.avatar ? <img src={person.avatar} alt={`${person.name}, ${person.role}`} /> : <span className="avatar-fallback"><Icon name={person.key === "human" ? "human" : "shield"} size={size === "lg" ? 34 : 20} /></span>}{status && <span className={cx("avatar-status", status)} />}</span>;
}
export function StatusPill({ tone = "info", children, icon, compact = false }) { return <span className={cx("status-pill", `status-${tone}`, compact && "status-compact")}>{icon && <Icon name={icon} size={compact ? 13 : 15} />}{children}</span>; }
export function Panel({ children, className = "", title, eyebrow, action, noPadding = false }) { return <section className={cx("panel", noPadding && "panel-no-padding", className)}>{(title || eyebrow || action) && <header className="panel-header"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}{title && <h2>{title}</h2>}</div>{action && <div className="panel-action">{action}</div>}</header>}{children}</section>; }
export function PageHeader({ title, subtitle, actions, meta }) { return <header className="page-header"><div className="page-header-copy">{meta && <div className="page-meta">{meta}</div>}<h1>{title}</h1>{subtitle && <p>{subtitle}</p>}</div>{actions && <div className="page-actions">{actions}</div>}</header>; }
export function PrimaryButton({ children, icon, href, onClick, tone = "primary", disabled = false, target, dataTestId, title }) {
  const className = cx("button", `button-${tone}`, disabled && "button-disabled");
  const contents = <>{icon && <Icon name={icon} size={18} />}{children}</>;
  if (disabled) {
    return <button type="button" className={className} disabled title={title} data-testid={dataTestId}>{contents}</button>;
  }
  if (href) {
    const gatewayRoute = [
      "/api/runs",
      "/api/ipfs",
      "/adversarial-safety-demo",
      "/certificate",
      "/canonical-proof",
      "/cspr-click",
      "/integrations/status",
      "/ipfs",
      "/judge-walkthrough",
      "/proof-center",
      "/proof-pack",
      "/proof-registry",
      "/safepay-lite",
      "/x402",
    ].some((prefix) => href.startsWith(prefix));
    const external = href.startsWith("http") || href.startsWith("/approve/") || gatewayRoute;
    if (external) return <a className={className} href={href} target={target || "_blank"} rel="noreferrer" title={title} data-testid={dataTestId}>{contents}</a>;
    return <Link className={className} href={href} title={title} data-testid={dataTestId}>{contents}</Link>;
  }
  return <button type="button" className={className} onClick={onClick} title={title} data-testid={dataTestId}>{contents}</button>;
}

export function HashChip({ label, value, href, tone = "info", displayValue }) {
  const text = String(value || "—");
  const visibleText = displayValue || shortHash(text, 12, 8);
  const copy = () => {
    if (typeof navigator !== "undefined" && navigator.clipboard && value) navigator.clipboard.writeText(text).catch(() => {});
  };
  return <span className={cx("hash-chip", `hash-chip-${tone}`)}>
    {label && <small>{label}</small>}
    {href ? <a href={href} target="_blank" rel="noreferrer">{visibleText}</a> : <code>{visibleText}</code>}
    {value && <button type="button" onClick={copy} aria-label={`Copy ${label || "hash"}`}><Icon name="copy" size={13} /></button>}
  </span>;
}

export function RichText({ value, hashChips = false }) {
  const text = normalizeJudgeText(String(value || ""));
  const tokenPattern = hashChips
    ? /(\*\*[^*]+\*\*|`[^`]+`|(?:sha256:)?[a-f0-9]{64})/gi
    : /(\*\*[^*]+\*\*|`[^`]+`)/gi;
  const parts = text.split(tokenPattern).filter((part) => part !== "");
  return <span className="rich-inline-text">{parts.map((part, index) => {
    if (/^\*\*[^*]+\*\*$/.test(part)) return <strong key={`${part}-${index}`}>{part.slice(2, -2)}</strong>;
    if (/^`[^`]+`$/.test(part)) return <code key={`${part}-${index}`} className="inline-code-chip">{part.slice(1, -1)}</code>;
    const hashMatch = hashChips ? part.match(/^(sha256:)?([a-f0-9]{64})$/i) : null;
    if (hashMatch) {
      const [, prefix, hash] = hashMatch;
      return <HashChip key={`${hash}-${index}`} value={hash} displayValue={prefix ? `sha256:${shortHash(hash, 4, 5)}` : shortHash(hash, 8, 5)} />;
    }
    return <span key={`${part}-${index}`}>{part}</span>;
  })}</span>;
}

export function LoadingValue() { return <span className="loading-value">Loading…</span>; }

// Honest placeholder for any surface whose live data has not loaded. Neutral
// tones only — never a success cue.
export function PendingNote({ children, icon = "clock", className = "" }) {
  return <div className={cx("pending-note", className)}><Icon name={icon} size={16} /><span>{children}</span></div>;
}

export function CodePreview({ summary = "Show raw payload", value }) {
  return <details className="code-preview"><summary>{summary}</summary><pre>{typeof value === "string" ? value : publicJson(value)}</pre></details>;
}
export function EmptyState({ title, description, icon = "info", action }) { return <div className="empty-state"><span className="empty-icon"><Icon name={icon} size={26} /></span><strong>{title}</strong>{description && <p>{description}</p>}{action}</div>; }
export function Skeleton({ height = 80, className = "" }) { return <div className={cx("skeleton", className)} style={{ height }} />; }
export function Toast({ toast, onClose }) {
  useEffect(() => { if (!toast) return undefined; const timer = setTimeout(onClose, 4200); return () => clearTimeout(timer); }, [toast, onClose]);
  if (!toast) return null;
  return <div className={cx("toast", `toast-${toast.type || "info"}`)} role="status"><span className="toast-icon"><Icon name={toast.type === "error" ? "signal" : "check"} size={18} /></span><span>{toast.message}</span><button type="button" onClick={onClose} aria-label="Dismiss notification"><Icon name="close" size={16} /></button></div>;
}

export function useRecordingMode() {
  const [recordingMode, setRecordingMode] = useState(false);
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    setRecordingMode(
      params.get("recording") === "1" ||
      params.get("mode") === "recording" ||
      window.location.pathname.endsWith("/record"),
    );
  }, []);
  return recordingMode;
}

export function useDelayedFlag(active, delayMs = 10000) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    if (!active) {
      setVisible(false);
      return undefined;
    }
    const timer = setTimeout(() => setVisible(true), delayMs);
    return () => clearTimeout(timer);
  }, [active, delayMs]);
  return visible;
}

export function useUtcClock() {
  const [time, setTime] = useState(null);
  useEffect(() => { const update = () => setTime(new Date()); update(); const timer = setInterval(update, 1000); return () => clearInterval(timer); }, []);
  return time ? `${time.toISOString().slice(0, 10)} ${time.toISOString().slice(11, 19)} UTC` : "—";
}
