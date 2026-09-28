import { useState } from "react";
import { ArrowRight, BadgeCheck, Braces, CircleDot, FileCheck2, History, ShieldCheck } from "lucide-react";
import { api } from "../services/api.js";
import { useResource } from "../hooks/useResource.js";
import { DataTable, Drawer, PageHeader, PlaceholderLabel, ResourceState, SectionTitle, StatusTag, Surface } from "../components/common/UI.jsx";

const columns = [
  { key: "name", label: "PARSER", render: (parser) => <div className="parser-name-cell"><span className="parser-format-icon"><Braces size={15} /></span><div><strong>{parser.name}</strong><span className="mono-cell">{parser.key}</span></div></div> },
  { key: "format", label: "FORMAT", render: (parser) => <span className="format-mark">{parser.format}</span> },
  { key: "version", label: "VERSION", render: (parser) => <span className="mono-cell">v{parser.version}</span> },
  { key: "status", label: "STATUS", render: (parser) => <StatusTag status={parser.status} /> },
  { key: "qualification", label: "QUALIFICATION", render: (parser) => <span className="qualification-cell"><BadgeCheck size={14} />{parser.qualification}<small>{parser.fixtures} fixtures</small></span> },
  { key: "lastUsed", label: "LAST USED" },
  { key: "processed", label: "EVENTS PROCESSED", className: "align-right mono-cell" },
];

const lifecycle = [
  { label: "Proposed", detail: "Format discovered", icon: CircleDot, state: "complete" },
  { label: "Approved", detail: "Human review", icon: ShieldCheck, state: "complete" },
  { label: "Qualified", detail: "Fixtures verified", icon: FileCheck2, state: "complete" },
  { label: "Active", detail: "Signed release", icon: BadgeCheck, state: "current" },
];

export default function Parsers() {
  const { data, loading, error } = useResource(api.getParserStatus);
  const [selected, setSelected] = useState(null);
  const [message, setMessage] = useState("");

  function showAction(parser, action) {
    setSelected({ ...parser, action });
    setMessage("");
  }

  return (
    <>
      <PageHeader eyebrow="PARSER REGISTRY" title="Parsers" description="Manage deterministic parsers through a governed lifecycle." action={<PlaceholderLabel />} />
      <Surface className="lifecycle-surface surface-space">
        <SectionTitle title="Parser lifecycle" detail="Every activation requires qualification and human approval." />
        <div className="lifecycle-flow">{lifecycle.map((step, index) => {
          const Icon = step.icon;
          return <div className="lifecycle-step-wrap" key={step.label}><div className={`lifecycle-step lifecycle-${step.state}`}><span><Icon size={16} /></span><div><strong>{step.label}</strong><small>{step.detail}</small></div></div>{index < lifecycle.length - 1 && <ArrowRight className="lifecycle-arrow" size={15} />}</div>;
        })}</div>
        <div className="lifecycle-footnote"><ShieldCheck size={14} /> Copilot suggestions can inform review, but can never activate a parser.</div>
      </Surface>

      <Surface className="surface-space parser-registry">
        <SectionTitle title="Registered parsers" detail={`${data?.length ?? 0} parser packs in the local registry`} action={<PlaceholderLabel />} />
        <ResourceState loading={loading} error={error}>
          <DataTable columns={columns} rows={data} onRowClick={(parser) => showAction(parser, "Parser details")} />
        </ResourceState>
      </Surface>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.action ?? "Parser details"} subtitle={selected?.key}>
        {selected && <div className="drawer-stack">
          <div className="detail-status-row"><StatusTag status={selected.status}>{selected.status}</StatusTag><span className="format-mark">{selected.format}</span><span className="mono-cell">v{selected.version}</span></div>
          <div className="detail-grid"><div><span>Qualification</span><strong>{selected.qualification}</strong></div><div><span>Fixtures passed</span><strong>{selected.fixtures}</strong></div><div><span>Events processed</span><strong>{selected.processed}</strong></div><div><span>Last used</span><strong>{selected.lastUsed}</strong></div></div>
          <div className="drawer-actions-row"><button className="button button-secondary" onClick={() => showAction(selected, "Qualification report")}><FileCheck2 size={14} /> View qualification</button><button className="button button-secondary" onClick={() => showAction(selected, "Parser history")}><History size={14} /> View history</button></div>
          <div className="review-callout"><ShieldCheck size={16} /><div><strong>Human review required</strong><p>Review does not activate or publish this parser.</p></div></div>
          <button className="button button-primary" onClick={() => setMessage("Review request recorded in this mock interface.")}><ShieldCheck size={14} /> Request review</button>
          {message && <p className="inline-confirmation" role="status">{message} API placeholder</p>}
          <PlaceholderLabel />
        </div>}
      </Drawer>
    </>
  );
}