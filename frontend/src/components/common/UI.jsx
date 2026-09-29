import { useEffect } from "react";
import { AlertCircle, Check, ChevronRight, Info, X } from "lucide-react";

export function PageHeader({ eyebrow, title, description, action, children }) {
  return (
    <div className="page-header">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {(action || children) && <div className="page-header-actions">{action}{children}</div>}
    </div>
  );
}

export function SectionTitle({ title, detail, action }) {
  return (
    <div className="section-title">
      <div>
        <h2>{title}</h2>
        {detail && <p>{detail}</p>}
      </div>
      {action}
    </div>
  );
}

export function StatusTag({ status, children }) {
  const value = status ?? children ?? "unknown";
  const key = String(value).toLowerCase().replaceAll(" ", "-");
  return <span className={`status-tag status-${key}`}><span className="status-dot" />{children ?? status}</span>;
}

export function PlaceholderLabel({ children = "Live API" }) {
  return <span className="placeholder-label"><Info size={12} strokeWidth={1.8} />{children}</span>;
}

export function Surface({ className = "", children }) {
  return <section className={`surface ${className}`}>{children}</section>;
}

export function MetricCard({ item, icon: Icon }) {
  return (
    <Surface className="metric-card">
      <div className="metric-topline">
        <span>{item.label}</span>
        {Icon && <span className={`metric-icon tone-${item.tone}`}><Icon size={16} strokeWidth={1.8} /></span>}
      </div>
      <div className="metric-value-line">
        <strong>{item.value}</strong>
        {item.unit && <span>{item.unit}</span>}
      </div>
      <div className="metric-bottomline">
        <span className={`trend trend-${item.direction}`}>
          {item.direction === "up" ? "↗" : item.direction === "down" ? "↘" : "·"} {item.change}
        </span>
        <span className="mini-bars" aria-hidden="true">
          {item.bars?.map((height, index) => <i key={index} style={{ height: `${height}%` }} />)}
        </span>
      </div>
    </Surface>
  );
}

export function EmptyState({ title, detail, action, icon: Icon = Info }) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><Icon size={19} /></span>
      <strong>{title}</strong>
      <p>{detail}</p>
      {action}
    </div>
  );
}

export function ResourceState({ loading, error, empty, children }) {
  if (loading) {
    return <div className="loading-state" aria-label="Loading"><span /><span /><span /></div>;
  }
  if (error) {
    return <EmptyState title="Couldn’t load this view" detail={error.message ?? "The API is not connected."} icon={AlertCircle} />;
  }
  if (empty) return <EmptyState title="Waiting for ingestion data" detail="The ingestion API is not connected yet." />;
  return children;
}

export function DataTable({ columns, rows, onRowClick, emptyMessage = "No matching events" }) {
  if (!rows?.length) {
    return <EmptyState title={emptyMessage} detail="Try adjusting the current filters." />;
  }
  return (
    <div className="table-scroll">
      <table>
        <thead><tr>{columns.map((column) => <th key={column.key} className={column.className}>{column.label}</th>)}</tr></thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.id ?? row.name}
              className={onRowClick ? "clickable-row" : ""}
              tabIndex={onRowClick ? 0 : undefined}
              onClick={() => onRowClick?.(row)}
              onKeyDown={(event) => {
                if (onRowClick && (event.key === "Enter" || event.key === " ")) {
                  event.preventDefault();
                  onRowClick(row);
                }
              }}
            >
              {columns.map((column) => <td key={column.key} className={column.className}>{column.render ? column.render(row) : row[column.key]}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Drawer({ open, onClose, title, subtitle, children, size = "regular" }) {
  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="drawer-layer">
      <button className="drawer-backdrop" aria-label="Close details" onClick={onClose} />
      <aside className={`drawer drawer-${size}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="drawer-header">
          <div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>
          <button className="icon-button" onClick={onClose} aria-label="Close"><X size={17} /></button>
        </div>
        <div className="drawer-content">{children}</div>
      </aside>
    </div>
  );
}

export function JsonViewer({ value }) {
  return <pre className="code-viewer"><code>{JSON.stringify(value, null, 2)}</code></pre>;
}

export function InlineLink({ children, onClick }) {
  return <button className="inline-link" onClick={onClick}>{children}<ChevronRight size={13} /></button>;
}

export function ConfirmedButton({ children, onClick, icon: Icon, className = "button-secondary" }) {
  return <button className={`button ${className}`} onClick={onClick}>{Icon && <Icon size={15} />}{children}<Check className="button-confirmed" size={14} /></button>;
}