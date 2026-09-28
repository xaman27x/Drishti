import { useState } from "react";
import { Activity, Database, Layers, Pause, Play, RotateCw, Server } from "lucide-react";
import { StatusTag, Surface } from "../common/UI.jsx";

export default function WorkerStatusCard({ worker }) {
  const [status, setStatus] = useState(worker.status);
  const [feedback, setFeedback] = useState("");

  function simulate(nextStatus, message) {
    setStatus(nextStatus);
    setFeedback(message);
    window.setTimeout(() => setFeedback(""), 2400);
  }

  return (
    <Surface className="worker-card">
      <div className="worker-head">
        <div className="worker-ident">
          <span className="worker-icon"><Server size={18} /></span>
          <div><span className="eyebrow">INGESTION WORKER</span><h3>{worker.workerId}</h3></div>
        </div>
        <StatusTag status={status}>{status === "running" ? "Running" : "Stopped"}</StatusTag>
      </div>

      <div className="worker-connection-flow">
        <div className="worker-connection"><span className="connection-icon"><Layers size={15} /></span><span>Kafka</span><StatusTag status={worker.kafkaConnected ? "healthy" : "failed"}>{worker.kafkaConnected ? "Connected" : "Disconnected"}</StatusTag></div>
        <span className="worker-flow-line" />
        <div className="worker-connection"><span className="connection-icon"><Database size={15} /></span><span>MinIO</span><StatusTag status={worker.minioConnected ? "healthy" : "failed"}>{worker.minioConnected ? "Connected" : "Disconnected"}</StatusTag></div>
      </div>

      <div className="worker-current-job"><span className="job-pulse"><Activity size={14} /></span><div><small>CURRENT JOB</small><strong>{status === "running" ? worker.currentJob : "Worker paused"}</strong></div><PlaceholderLabelMini /></div>
      <div className="worker-metrics">
        <div><strong>{worker.eventsProcessed.toLocaleString()}</strong><span>Events processed</span></div>
        <div><strong>{worker.eventsFailed}</strong><span>Events failed</span></div>
        <div><strong>{worker.lastHeartbeat}</strong><span>Last heartbeat</span></div>
      </div>
      <div className="worker-footer">
        <span><i className={status === "running" ? "heartbeat-dot" : "heartbeat-dot heartbeat-paused"} />{status === "running" ? "Heartbeat healthy" : "Heartbeat paused"}</span>
        <div className="worker-actions">
          {status === "running" ? (
            <button className="button button-secondary button-small" onClick={() => simulate("stopped", "Worker stop simulated") }><Pause size={13} /> Stop</button>
          ) : (
            <button className="button button-secondary button-small" onClick={() => simulate("running", "Worker start simulated")}><Play size={13} /> Start</button>
          )}
          <button className="button button-secondary button-small" onClick={() => simulate("running", "Worker restart simulated")}><RotateCw size={13} /> Restart</button>
        </div>
      </div>
      {feedback && <div className="worker-feedback" role="status">{feedback} · mock action only</div>}
    </Surface>
  );
}

function PlaceholderLabelMini() {
  return <span className="worker-placeholder">MOCK</span>;
}