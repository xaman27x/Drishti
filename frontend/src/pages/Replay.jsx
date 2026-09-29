import { useState } from "react";
import { api } from "../services/api.js";
import { useResource } from "../hooks/useResource.js";
import { JsonViewer, PageHeader, ResourceState, Surface } from "../components/common/UI.jsx";
export default function Replay() {
  const jobs = useResource(api.getReplay);
  const parsers = useResource(api.getParserStatus);
  const [ids, setIds] = useState("");
  const [revision, setRevision] = useState("1");
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  async function submit(e) {
    e.preventDefault();
    try { const result = await api.createReplay({event_ids: ids.split(/[\s,]+/).filter(Boolean), registry_revision: Number(revision), reason}); setMessage(`Request ${result.id} created; separate approval required.`); }
    catch (error) {setMessage(error.message);}
  }
  async function approve(id) {try {await api.approveReplay(id); setMessage("Signed approval stored; worker will process the replay.");} catch(error) {setMessage(error.message);}}
  return <><PageHeader title="Controlled replay" description="Create a bounded request, then explicitly approve it with the local demo reviewer role." />
    <Surface className="surface-space"><form onSubmit={submit} className="drawer-stack">
      <label className="field-label">Event UUIDs<textarea required value={ids} onChange={e => setIds(e.target.value)} /></label>
      <label className="field-label">Pinned registry release<select value={revision} onChange={e => setRevision(e.target.value)}>{parsers.data?.map(p => <option key={p.id} value={p.registryRevision}>{p.key} · {p.version} · release {p.registryRevision}</option>)}</select></label>
      <label className="field-label">Reason<textarea required minLength={8} value={reason} onChange={e => setReason(e.target.value)} /></label>
      <button className="button button-primary">Request replay</button></form><p role="status">{message}</p></Surface>
    <ResourceState loading={jobs.loading} error={jobs.error}>{jobs.data?.map(job => <Surface className="surface-space" key={job.id}><h3>{job.id} · {job.status}</h3>{job.status === "requested" && <button className="button button-secondary" onClick={() => approve(job.id)}>Approve as replay-approver</button>}<JsonViewer value={job} /></Surface>)}</ResourceState></>;
}
