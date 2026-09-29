import { useState } from "react";
import { api } from "../services/api.js";
import { useResource } from "../hooks/useResource.js";
import { JsonViewer, PageHeader, ResourceState, Surface } from "../components/common/UI.jsx";
export default function Provenance() {
  const [eventId, setEventId] = useState("");
  const [selected, setSelected] = useState("");
  const {data, loading, error} = useResource(() => selected ? api.getEvidence(selected) : Promise.resolve(null), [selected]);
  return <><PageHeader eyebrow="EVIDENCE LINEAGE" title="Provenance" description="Retrieve the original bytes and inspect field claims." />
    <Surface className="surface-space"><form onSubmit={e => {e.preventDefault(); setSelected(eventId.trim());}} className="drawer-stack"><label className="field-label">Event UUID<input required value={eventId} onChange={e => setEventId(e.target.value)} /></label><button className="button button-primary">Inspect evidence</button></form></Surface>
    <ResourceState loading={loading} error={error}>{data && <Surface className="surface-space"><p>Raw SHA-256: {data.raw_sha256}</p><p>Integrity verified against archived bytes: {String(data.integrity_verified)}</p><a href={`/v1/events/${selected}/raw`}>Download original bytes</a><pre className="raw-evidence-view">{data.raw_text}</pre>
      {(data.certificate?.claims ?? []).map((claim, index) => <div className="manifest-row" key={index}><span>{claim.target_path ?? claim.disposition} [{claim.start}, {claim.end})</span><code>{claim.transformation ?? claim.rule_uid}</code></div>)}
      <JsonViewer value={data.certificate} /></Surface>}</ResourceState></>;
}
