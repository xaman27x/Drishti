import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Braces, Clock3, FileCode2, Filter, GitBranch, Search, ShieldCheck, X } from "lucide-react";
import { useResource } from "../hooks/useResource.js";
import { api } from "../services/api.js";
import { DataTable, Drawer, JsonViewer, PageHeader, PlaceholderLabel, ResourceState, SectionTitle, StatusTag } from "../components/common/UI.jsx";

const columns = [
  { key: "id", label: "EVENT ID", render: (event) => <span className="mono-cell event-id">{event.id}</span> },
  { key: "timestamp", label: "TIMESTAMP", render: (event) => <span className="mono-cell">{new Date(event.timestamp).toISOString().replace("T", " ").slice(0, 19)}</span> },
  { key: "source", label: "SOURCE", render: (event) => <div className="source-cell"><strong>{event.source}</strong><span>{event.sourceType}</span></div> },
  { key: "format", label: "FORMAT", render: (event) => <span className="format-mark">{event.format}</span> },
  { key: "parser", label: "PARSER", render: (event) => <span className="mono-cell">{event.parser}</span> },
  { key: "severity", label: "SEVERITY", render: (event) => <StatusTag status={event.severity}>{event.severity}</StatusTag> },
  { key: "className", label: "OCSF CLASS" },
  { key: "status", label: "STATUS", render: (event) => <StatusTag status={event.status} /> },
];

const tabs = ["Overview", "Raw evidence", "Normalized event", "Provenance", "Processing"];

export default function Events() {
  const { data, loading, error } = useResource(api.getEvents);
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") ?? "");
  const [format, setFormat] = useState("All formats");
  const [status, setStatus] = useState("All statuses");
  const [timeRange, setTimeRange] = useState("Last 24 hours");
  const [source, setSource] = useState("All sources");
  const [parser, setParser] = useState("All parsers");
  const [selected, setSelected] = useState(null);
  const [activeTab, setActiveTab] = useState("Overview");

  const rows = useMemo(() => (data ?? []).filter((event) => {
    const needle = query.toLowerCase();
    return (!needle || [event.id, event.source, event.parser, event.format, event.className].some((value) => value.toLowerCase().includes(needle)))
      && (format === "All formats" || event.format === format)
      && (status === "All statuses" || event.status === status)
      && (source === "All sources" || event.source === source)
      && (parser === "All parsers" || event.parser === parser);
  }), [data, query, format, status, source, parser]);

  function openEvent(event) {
    setSelected(event);
    setActiveTab("Overview");
  }

  return (
    <>
      <PageHeader eyebrow="EVIDENCE EXPLORER" title="Events" description="Search and inspect events across the processing pipeline." action={<PlaceholderLabel />} />
      <section className="event-explorer">
        <div className="event-toolbar">
          <label className="event-search"><Search size={15} /><input aria-label="Search events" placeholder="Search events, IDs, sources…" value={query} onChange={(event) => setQuery(event.target.value)} />{query && <button aria-label="Clear search" onClick={() => setQuery("")}><X size={14} /></button>}</label>
          <span className="toolbar-divider" />
          <FilterSelect label="Time range" value={timeRange} options={["Last 24 hours", "Last 7 days", "Last 30 days"]} onChange={setTimeRange} icon={Clock3} />
          <FilterSelect label="Format" value={format} options={["All formats", "RFC5424", "CEF", "JSON", "CSV"]} onChange={setFormat} icon={FileCode2} />
          <FilterSelect label="Status" value={status} options={["All statuses", "Normalized", "Processing", "Quarantined", "Failed"]} onChange={setStatus} icon={Filter} />
          <button className="filter-advanced" onClick={() => { setSource(source === "All sources" ? "edge-fw-01" : "All sources"); }}><Filter size={14} /> Source</button>
          <button className="filter-advanced" onClick={() => { setParser(parser === "All parsers" ? "rfc5424-firewall" : "All parsers"); }}><Braces size={14} /> Parser</button>
        </div>
        <div className="event-applied-filters">
          <span>{rows.length} events</span>
          {source !== "All sources" && <button className="filter-chip" onClick={() => setSource("All sources")}>{source}<X size={12} /></button>}
          {parser !== "All parsers" && <button className="filter-chip" onClick={() => setParser("All parsers")}>{parser}<X size={12} /></button>}
          <span className="filters-placeholder"><PlaceholderLabel /></span>
        </div>
        <ResourceState loading={loading} error={error}>
          <DataTable columns={columns} rows={rows} onRowClick={openEvent} />
        </ResourceState>
        <div className="event-table-footer"><span>Showing {rows.length} of {data?.length ?? 0} illustrative records</span><span>Click a row to inspect event details <span className="key-cap">↵</span></span></div>
      </section>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title="Event details" subtitle={selected?.id} size="wide">
        {selected && <>
          <div className="event-detail-top"><div><StatusTag status={selected.status} /><span className="format-mark">{selected.format}</span><span className="mono-cell">{new Date(selected.timestamp).toISOString().replace("T", " ").slice(0, 19)} UTC</span></div><span className="event-source-label">{selected.source} · {selected.sourceType}</span></div>
          <div className="detail-tabs" role="tablist">{tabs.map((tab) => <button key={tab} role="tab" aria-selected={activeTab === tab} className={activeTab === tab ? "detail-tab active" : "detail-tab"} onClick={() => setActiveTab(tab)}>{tab}</button>)}</div>
          <EventTab event={selected} tab={activeTab} />
        </>}
      </Drawer>
    </>
  );
}

function FilterSelect({ label, value, options, onChange, icon: Icon }) {
  return <label className="select-filter" aria-label={label}><Icon size={13} /><select value={value} onChange={(event) => onChange?.(event.target.value)}>{options.map((option) => <option key={option}>{option}</option>)}</select></label>;
}

function EventTab({ event, tab }) {
  if (tab === "Raw evidence") return <div className="event-tab-content"><div className="code-heading"><span>RAW BYTES · UTF-8 VIEW</span><PlaceholderLabel /></div><pre className="raw-evidence-view">{event.raw}</pre><p className="drawer-note">Original evidence is immutable. Display is illustrative mock data.</p></div>;
  if (tab === "Normalized event") return <div className="event-tab-content"><div className="code-heading"><span>OCSF EVENT · 1.9.0</span><PlaceholderLabel /></div><JsonViewer value={event.normalized} /></div>;
  if (tab === "Provenance") return <div className="event-tab-content"><div className="provenance-mini-line"><span><InboxIcon /></span><i /><span><ShieldCheck size={15} /></span><i /><span><Braces size={15} /></span><i /><span><GitBranch size={15} /></span></div><div className="detail-grid"><div><span>Content hash</span><strong className="mono-cell">sha256:8d1d6c1f…f29aa</strong></div><div><span>Parser identity</span><strong className="mono-cell">{event.parser}</strong></div><div><span>Byte accounting</span><strong>100% accounted</strong></div><div><span>Archive status</span><strong>Immutable evidence</strong></div></div><PlaceholderLabel /></div>;
  if (tab === "Processing") return <div className="event-tab-content"><div className="processing-list">{[["Accepted", "18:42:16.001", "Kafka · drishti.raw.accepted.v1"], ["Archived", "18:42:16.005", "MinIO · raw evidence stored"], ["Parsed", "18:42:16.010", `${event.parser} · deterministic parse`], ["Normalized", "18:42:16.014", "OCSF schema 1.9.0 · validated"]].map(([label, time, detail]) => <div className="processing-item" key={label}><i /><div><strong>{label}</strong><span>{detail}</span></div><time>{time} UTC</time></div>)}</div><PlaceholderLabel /></div>;
  return <div className="event-tab-content"><div className="detail-grid"><div><span>Source</span><strong>{event.source} · {event.sourceType}</strong></div><div><span>Parser</span><strong className="mono-cell">{event.parser}</strong></div><div><span>Severity</span><strong><StatusTag status={event.severity}>{event.severity}</StatusTag></strong></div><div><span>OCSF class</span><strong>{event.className}</strong></div><div><span>Processing time</span><strong>{event.duration}</strong></div><div><span>Trace ID</span><strong className="mono-cell">trc_7e2c91a4…</strong></div></div><div className="drawer-subsection"><h3>Raw preview</h3><pre className="raw-evidence-view compact">{event.raw}</pre></div><PlaceholderLabel /></div>;
}

function InboxIcon() {
  return <ShieldCheck size={15} />;
}