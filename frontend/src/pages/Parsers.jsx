import { useState } from "react";
import { api } from "../services/api.js";
import { useResource } from "../hooks/useResource.js";
import { PageHeader, Surface, JsonViewer, ResourceState } from "../components/common/UI.jsx";
export default function Parsers() {
  const resource = useResource(api.getParserStatus);
  const [pack, setPack] = useState("");
  const [message, setMessage] = useState("");
  const [sampleIds, setSampleIds] = useState("");
  const [proof, setProof] = useState(null);
  async function propose(e) {e.preventDefault(); try {const result = await api.propose(JSON.parse(pack));setMessage(`Proposal ${result.proposal_id} submitted. Continue on Governance.`);} catch(error) {setMessage(error.message);}}
  return <><PageHeader title="Parser registry" description="Approved and qualified releases, with verifiable history." />
    <ResourceState loading={resource.loading} error={resource.error}>{resource.data?.map(p => <Surface className="surface-space" key={p.id}><h2>{p.name} · {p.version} · {p.status}</h2><p>{p.key} · release {p.registryRevision}</p><button className="button button-secondary" onClick={() => setPack(JSON.stringify({...p.pack, version: "1.1.0"}, null, 2))}>Draft upgrade</button> <button className="button button-secondary" onClick={async () => {try {setProof(await api.getProof(p.registryRevision));} catch(e) {setMessage(e.message);}}}>Verify history</button><details><summary>Signed release and qualification</summary><JsonViewer value={p.release} /></details></Surface>)}</ResourceState>
    <Surface className="surface-space"><h2>Local schema proposal</h2><p>Recognizes RFC5424 or CEF samples. Proposals still need review, qualification and activation.</p><label className="field-label">Archived sample UUIDs<textarea value={sampleIds} onChange={e => setSampleIds(e.target.value)} /></label><button className="button button-secondary" onClick={async () => {try {const result = await api.copilot(sampleIds.split(/[\s,]+/).filter(Boolean), "1.1.0"); setMessage(`Proposal ${result.proposal.proposal_id} created. Continue on Governance.`);} catch(e) {setMessage(e.message);}}}>Propose version 1.1.0</button></Surface>
    {proof && <JsonViewer value={proof} />}<Surface className="surface-space"><h2>Propose a declarative parser pack</h2><form onSubmit={propose} className="drawer-stack"><textarea aria-label="Parser pack JSON" rows={12} value={pack} onChange={e => setPack(e.target.value)} required /><button className="button button-primary">Submit proposal</button></form><p role="status">{message}</p></Surface></>;
}
