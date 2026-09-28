import { useResource } from "../hooks/useResource.js";
import { api } from "../services/api.js";
import { PageHeader, PlaceholderLabel, ResourceState, SectionTitle, Surface } from "../components/common/UI.jsx";
import { BadgeCheck, Bot, FileCheck2, GitCommitHorizontal, History, RotateCcw, ShieldCheck, UserRoundCheck } from "lucide-react";

const icons = { proposed: Bot, qualified: FileCheck2, approved: UserRoundCheck, released: GitCommitHorizontal, replay: RotateCcw };
const colors = { proposed: "amber", qualified: "green", approved: "green", released: "blue", replay: "blue" };

export default function Governance() {
  const { data, loading, error } = useResource(api.getGovernanceAudit);

  return (
    <>
      <PageHeader eyebrow="AUDIT & APPROVALS" title="Governance" description="A human-reviewed record of parser qualification, approvals, and releases." action={<PlaceholderLabel />} />
      <Surface className="governance-policy surface-space"><span className="policy-icon"><ShieldCheck size={17} /></span><div><strong>Human control stays in the loop</strong><p>AI and Copilot suggestions can support parser proposals, but never approve, qualify, or activate a parser.</p></div><span className="policy-state"><i /> Enforced by workflow</span></Surface>

      <div className="audit-summary-grid">
        <Summary label="Approvals today" value="12" caption="All human-reviewed" icon={UserRoundCheck} />
        <Summary label="Qualified parsers" value="08" caption="Fixture suites passed" icon={BadgeCheck} />
        <Summary label="Registry releases" value="03" caption="Signed this week" icon={GitCommitHorizontal} />
        <Summary label="Audit retention" value="365d" caption="Tamper-evident records" icon={History} />
      </div>

      <Surface className="surface-space audit-surface">
        <SectionTitle title="Audit timeline" detail="Recent actions across parser governance and replay" action={<PlaceholderLabel />} />
        <ResourceState loading={loading} error={error}>
          <div className="audit-timeline">{data?.map((event, index) => {
            const Icon = icons[event.kind] ?? FileCheck2;
            return <div className="audit-item" key={`${event.action}-${index}`}><div className={`audit-marker audit-${colors[event.kind]}`}><Icon size={14} /></div><div className="audit-body"><div className="audit-item-head"><strong>{event.action}</strong><time>{event.time}</time></div><span className="audit-subject">{event.subject}</span><p>{event.detail}</p><div className="audit-actor">Performed by <strong>{event.actor}</strong></div></div></div>;
          })}</div>
        </ResourceState>
      </Surface>
    </>
  );
}

function Summary({ label, value, caption, icon: Icon }) {
  return <Surface className="audit-summary"><span className="audit-summary-icon"><Icon size={16} /></span><span>{label}</span><strong>{value}</strong><small>{caption}</small></Surface>;
}