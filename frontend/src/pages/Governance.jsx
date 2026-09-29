import { useState } from "react";
import { api } from "../services/api.js";
import { useResource } from "../hooks/useResource.js";
import { PageHeader, Surface, JsonViewer, ResourceState } from "../components/common/UI.jsx";
export default function Governance() {
  const proposals = useResource(api.getProposals);
  const audit = useResource(api.getGovernanceAudit);
  const [ids, setIds] = useState("");
  const [message, setMessage] = useState("");
  async function action(id, value) {try {const result = await api.proposalAction(id, {action: value, event_ids: ids.split(/[\s,]+/).filter(Boolean)});setMessage(`${result.proposal_id}: ${result.status}`);} catch(e) {setMessage(e.message);}}
  return <><PageHeader title="Governance" description="Explicit local reviewer actions. Demo roles use server-held keys." />
    <Surface className="surface-space"><p>Parser upgrades require a server-computed comparison over at least 100 distinct archived events from the matching source type.</p><label className="field-label">Comparison event IDs<textarea value={ids} onChange={e => setIds(e.target.value)} /></label><p role="status">{message}</p></Surface>
    <ResourceState loading={proposals.loading} error={proposals.error}>{proposals.data?.map(p => <Surface className="surface-space" key={p.proposal_id}><h3>{p.pack.display_name} · {p.pack.version} · {p.status}</h3><div className="drawer-actions-row">{(p.status === "proposed" ? ["approve", "reject"] : p.status === "approved" ? ["qualify"] : p.status === "qualified" ? ["activate"] : []).map(value => <button className="button button-secondary" key={value} onClick={() => action(p.proposal_id, value)}>{value}</button>)}</div><details><summary>Proposal / qualification</summary><JsonViewer value={p} /></details></Surface>)}</ResourceState>
    <Surface className="surface-space"><h2>Verified audit history</h2><ResourceState loading={audit.loading} error={audit.error}><JsonViewer value={audit.data} /></ResourceState></Surface></>;
}
