import { useState } from "react";
import { Check, ClipboardList, FileCheck2, GitBranch, RotateCcw, ShieldCheck } from "lucide-react";
import { replayDefaults } from "../data/mockData.js";
import { PageHeader, PlaceholderLabel, StatusTag, Surface } from "../components/common/UI.jsx";

export default function Replay() {
  const [form, setForm] = useState({ eventIds: "evt_01HX8K2Q9M4P", source: replayDefaults.sourceKey, parser: "1.0.0", schema: "1.9.0", reason: "Validate updated parser behavior against archived evidence." });
  const [created, setCreated] = useState(false);
  const update = (key) => (event) => { setCreated(false); setForm((current) => ({ ...current, [key]: event.target.value })); };
  const eventIds = form.eventIds.split(/[\s,]+/).filter(Boolean);

  function submit(event) {
    event.preventDefault();
    setCreated(true);
  }

  return (
    <>
      <PageHeader eyebrow="CONTROLLED REPROCESSING" title="Replay" description="Reprocess immutable evidence using a pinned parser and schema revision." action={<PlaceholderLabel />} />
      <div className="replay-layout">
        <form className="replay-form" onSubmit={submit}>
          <Surface className="surface-space replay-form-surface">
            <div className="form-section-title"><span className="form-step">01</span><div><h2>Replay scope</h2><p>Choose the archived evidence and pinned revisions.</p></div></div>
            <label className="field-label">Event IDs<textarea rows="3" value={form.eventIds} onChange={update("eventIds")} placeholder="One event ID per line" required /><small>Separate IDs with commas or line breaks.</small></label>
            <label className="field-label">Source key<select value={form.source} onChange={update("source")}><option>generic.rfc5424-firewall</option><option>northstar.identity-gateway</option><option>generic.edr-json</option></select></label>
            <div className="field-grid"><label className="field-label">Parser revision<select value={form.parser} onChange={update("parser")}><option>1.0.0</option><option>1.1.0-rc1</option><option>2.1.0</option></select></label><label className="field-label">Schema revision<select value={form.schema} onChange={update("schema")}><option>1.9.0</option><option>1.8.0</option></select></label></div>
            <label className="field-label">Reason<textarea rows="3" value={form.reason} onChange={update("reason")} placeholder="Why is this replay needed?" required /></label>
          </Surface>
          <Surface className="replay-approval-note"><ShieldCheck size={16} /><div><strong>Controlled replay</strong><p>Replay uses immutable archived evidence and a pinned parser. Production activation is not part of this action.</p></div></Surface>
          <button className="button button-primary replay-submit" type="submit"><RotateCcw size={15} /> Create replay</button>
          {created && <div className="replay-success" role="status"><Check size={15} /> Replay request simulated <span>· API placeholder</span></div>}
        </form>

        <Surface className="manifest-card">
          <div className="manifest-head"><span className="manifest-icon"><ClipboardList size={16} /></span><div><span className="eyebrow">PREVIEW</span><h2>Replay manifest</h2></div><PlaceholderLabel /></div>
          <div className="manifest-event-count"><strong>{eventIds.length.toString().padStart(2, "0")}</strong><span>evidence records</span></div>
          <ManifestRow label="Event IDs" value={eventIds.length ? eventIds.join(", ") : "No events selected"} mono />
          <ManifestRow label="Source key" value={form.source} mono />
          <ManifestRow label="Registry revision" value={replayDefaults.registryRevision} mono />
          <ManifestRow label="Parser digest" value={replayDefaults.parserDigest} mono />
          <ManifestRow label="Output revision" value={`ocsf-${form.schema}`} mono />
          <ManifestRow label="Requester" value={replayDefaults.requester} />
          <ManifestRow label="Approver" value={replayDefaults.approver} />
          <div className="manifest-foot"><FileCheck2 size={14} /> Manifest values are mock data and require backend approval controls.</div>
        </Surface>
      </div>
    </>
  );
}

function ManifestRow({ label, value, mono }) {
  return <div className="manifest-row"><span>{label}</span><strong className={mono ? "mono-cell" : ""}>{value}</strong></div>;
}