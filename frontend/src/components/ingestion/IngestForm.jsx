import { useState } from "react";
import { api } from "../../services/api.js";
import { JsonViewer, Surface } from "../common/UI.jsx";
const samples = {
  "generic.rfc5424-firewall": "<134>1 2026-09-26T14:00:00Z edge-fw-01 drishti-fw 1234 NETFLOW - src=10.0.0.1 dst=10.0.0.2 spt=49152 dpt=443 proto=TCP action=allow",
  "generic.cef-firewall": "CEF:0|Acme|EdgeShield|1.2|100|Allowed TLS|5|src=10.0.0.1 dst=10.0.0.2 spt=49152 dpt=443 proto=TCP rt=1790431200000",
  unknown: "unrecognized vendor event 123",
};
export default function IngestForm() {
  const [source, setSource] = useState("generic.rfc5424-firewall");
  const [device, setDevice] = useState("edge-fw-01");
  const [raw, setRaw] = useState(samples[source]);
  const [key, setKey] = useState(crypto.randomUUID());
  const [receipt, setReceipt] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError("");
    try { setReceipt(await api.ingest(raw, source, device, key)); }
    catch (error) { setError(error.message); }
    finally { setBusy(false); }
  }
  return <Surface className="surface-space"><h2>Submit a log</h2><p>A 202 receipt confirms archival. The worker processes it asynchronously.</p>
    <form onSubmit={submit} className="drawer-stack">
      <label className="field-label">Source type<select value={source} onChange={e => {setSource(e.target.value); setRaw(samples[e.target.value]); setKey(crypto.randomUUID());}}>{Object.keys(samples).map(s => <option key={s}>{s}</option>)}</select></label>
      <label className="field-label">Device ID<input value={device} onChange={e => setDevice(e.target.value)} required /></label>
      <label className="field-label">Raw log<textarea rows={4} value={raw} onChange={e => setRaw(e.target.value)} required /></label>
      <label className="field-label">Idempotency key<input value={key} onChange={e => setKey(e.target.value)} required /></label>
      <div className="drawer-actions-row"><button disabled={busy} className="button button-primary">{busy ? "Submitting…" : "Submit / retry"}</button><button type="button" className="button button-secondary" onClick={() => {setKey(crypto.randomUUID()); setReceipt(null);}}>New event key</button></div>
    </form>{error && <p role="alert">{error}</p>}{receipt && <JsonViewer value={receipt} />}
  </Surface>;
}
