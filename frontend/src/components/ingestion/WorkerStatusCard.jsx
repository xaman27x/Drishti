import { useState } from "react";
import { api } from "../../services/api.js";
import { StatusTag, Surface } from "../common/UI.jsx";

export default function WorkerStatusCard({ worker }) {
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function control(action) {
    setBusy(true);
    try { await api.workerControl(action); setMessage(`${action} requested; waiting for worker heartbeat`); }
    catch (error) { setMessage(error.message); }
    finally { setBusy(false); }
  }
  return <Surface className="worker-card">
    <div className="worker-head"><h3>{worker.workerId}</h3><StatusTag status={worker.status} /></div>
    <p>{worker.currentJob}</p>
    <div className="worker-metrics">
      <div><strong>{worker.eventsProcessed}</strong><span>Normalized</span></div>
      <div><strong>{worker.eventsFailed}</strong><span>Quarantined</span></div>
      <div><strong>{worker.lastHeartbeat}</strong><span>Heartbeat UTC</span></div>
    </div>
    <div className="worker-footer"><span>Kafka reachable: {String(worker.kafkaConnected)} · MinIO reachable: {String(worker.minioConnected)}</span>
      <button disabled={busy} className="button button-secondary" onClick={() => control(worker.status === "paused" ? "resume" : "pause")}>{worker.status === "paused" ? "Resume" : "Pause"}</button>
    </div><p role="status">{message}</p>
  </Surface>;
}
