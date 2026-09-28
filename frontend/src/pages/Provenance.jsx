import { useResource } from "../hooks/useResource.js";
import { api } from "../services/api.js";
import { GitBranch, LockKeyhole, Database, Braces, Hash, ScanSearch, Radio, FileCheck2 } from "lucide-react";
import { PageHeader, PlaceholderLabel, ResourceState, SectionTitle, Surface } from "../components/common/UI.jsx";

const steps = [
  { title: "Raw event", detail: "Received", icon: Radio },
  { title: "Content hash", detail: "SHA-256", icon: Hash },
  { title: "Event UUID", detail: "Stable ID", icon: FileCheck2 },
  { title: "Kafka", detail: "Accepted", icon: GitBranch },
  { title: "Archive", detail: "MinIO object", icon: Database },
  { title: "Parser", detail: "Pinned identity", icon: Braces },
  { title: "Normalization", detail: "Field lineage", icon: ScanSearch },
  { title: "OCSF event", detail: "Validated", icon: LockKeyhole },
];

export default function Provenance() {
  const { data, loading, error } = useResource(api.getProvenance);
  const record = data ?? { event: { id: "" }, source: "", processedAt: "1970-01-01T00:00:00.000Z", contentHash: "", parserIdentity: "", parserDigest: "", schemaVersion: "", archiveLocation: "" };

  return (
    <>
      <PageHeader eyebrow="EVIDENCE LINEAGE" title="Provenance" description="Follow an event from original bytes to its normalized representation." action={<PlaceholderLabel />} />
      <ResourceState loading={loading} error={error}>
        <Surface className="lineage-surface surface-space">
          <div className="lineage-head"><div><span className="eyebrow">EVENT LINEAGE</span><h2>{record.event.id}</h2><p>{record.source} <span>·</span> {new Date(record.processedAt).toISOString().replace("T", " ").slice(0, 19)} UTC</p></div><span className="lineage-shield"><LockKeyhole size={17} /> Integrity verified</span></div>
          <div className="lineage-scroll"><div className="lineage-track">{steps.map((step, index) => {
            const Icon = step.icon;
            return <div className="lineage-step" key={step.title}><div className="lineage-node"><Icon size={16} /></div><strong>{step.title}</strong><span>{step.detail}</span>{index < steps.length - 1 && <i className="lineage-connector" />}</div>;
          })}</div></div>
          <div className="lineage-foot"><span><i className="stage-dot stage-healthy" /> Chain verified</span><span>All displayed values are illustrative</span></div>
        </Surface>

        <SectionTitle title="Evidence record" detail="Integrity and parser metadata for the selected event" />
        <div className="provenance-record-grid">
          <MetadataCard label="Content hash" value={record.contentHash} icon={Hash} mono />
          <MetadataCard label="Event UUID" value={record.event.id} icon={FileCheck2} mono />
          <MetadataCard label="Parser identity" value={record.parserIdentity} icon={Braces} mono />
          <MetadataCard label="Parser digest" value={record.parserDigest} icon={GitBranch} mono />
          <MetadataCard label="OCSF schema" value={record.schemaVersion} icon={ScanSearch} />
          <MetadataCard label="Processed at" value={new Date(record.processedAt).toISOString().replace("T", " ").slice(0, 23) + " UTC"} icon={LockKeyhole} mono />
          <Surface className="archive-card"><div className="metadata-icon"><Database size={15} /></div><span>Archive location</span><strong className="mono-cell">{record.archiveLocation}</strong><div className="archive-card-foot"><span><i className="stage-dot stage-healthy" /> Immutable evidence</span><PlaceholderLabel /></div></Surface>
        </div>

        <Surface className="lineage-note"><GitBranch size={16} /><p>Every normalized field can be traced to its source bytes. Parser qualification and signed registry identity travel with the event.</p><PlaceholderLabel /></Surface>
      </ResourceState>
    </>
  );
}

function MetadataCard({ label, value, icon: Icon, mono }) {
  return <Surface className="metadata-card"><div className="metadata-icon"><Icon size={15} /></div><span>{label}</span><strong className={mono ? "mono-cell" : ""}>{value}</strong><PlaceholderLabel /></Surface>;
}