import type { ReactNode } from "react"

import { amount, list, present, timestamp } from "@/lib/format"
import {
  CALL_STATUS, consentReason, DELIVERY, LIMITS, POLICY, PURPOSE, REQUEST_STATUS, ROUTE, runLabel, SIGNALS, VERIFICATION,
} from "@/lib/labels"
import type { Receipt as ReceiptData, ReceiptCall } from "@/types"

import { disclosureText } from "../state/model"

/* Content-free decision record (chat_ui.public_receipt), shown on demand.
 * Unknown values say "No disponible"; a missing cost is never rendered as zero. */

const NA = "No disponible"

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-1.5">
      <h4 className="text-xs font-semibold text-foreground">{title}</h4>
      <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 text-[0.8125rem]">{children}</dl>
    </section>
  )
}

function Fact({ name, value }: { name: string; value: unknown }) {
  return (
    <>
      <dt className="text-muted-foreground">{name}</dt>
      <dd className="min-w-0 break-words text-foreground tabular-nums">{present(value) ? String(value) : NA}</dd>
    </>
  )
}

export function RequestReceipt({ receipt, status }: { receipt: ReceiptData; status: string }) {
  const calls = list<ReceiptCall>(receipt.calls)
  const coverage = receipt.coverage
  const limits = Object.entries(LIMITS).filter(([key]) => receipt.limits?.[key] !== null && receipt.limits?.[key] !== undefined)
  const judge = calls.filter((call) => call.purpose === "verification" && call.status === "completed").slice(-1)[0]
  const generation = calls.filter((call) => call.purpose === "generation").slice(-1)[0]
  const total = receipt.total
  return (
    <div className="flex flex-col gap-4">
      <Section title="Petición">
        <Fact name="Estado" value={REQUEST_STATUS[status] ?? status} />
        <Fact name="Política local" value={POLICY[receipt.policy?.status ?? ""] ?? receipt.policy?.status} />
        {list<string>(receipt.policy?.reason_codes).length > 0 && <Fact name="Motivos" value={receipt.policy!.reason_codes!.join(", ")} />}
        {list<{ name?: string; id?: string | number }>(receipt.policy?.rules).map((rule, index) => (
          <Fact key={`rule-${index}`} name="Regla coincidente" value={rule?.name || rule?.id} />
        ))}
        {list<string>(receipt.notices).map((notice, index) => <Fact key={`notice-${index}`} name="Aviso" value={notice} />)}
        {receipt.consent_reason && (
          <Fact
            name={status === "pending_consent" ? "Confirmación" : "Aviso de confirmación anterior"}
            value={consentReason(receipt.consent_reason, status === "pending_consent")}
          />
        )}
      </Section>
      {coverage && (
        <Section title="Documento">
          <Fact name="Cobertura" value={coverage.status} />
          <Fact name="Unidades leídas / total" value={`${coverage.units_read ?? NA} / ${coverage.units_total ?? NA}`} />
          {list<string>(coverage.warnings).length > 0 && <Fact name="Advertencias" value={coverage.warnings!.join(", ")} />}
          {list<{ code: string }>(coverage.disclosures).filter((item) => item && typeof item.code === "string").map((item, index) => (
            <Fact key={`disclosure-${index}`} name="Aviso del documento" value={disclosureText(item)} />
          ))}
        </Section>
      )}
      {receipt.history && (
        <Section title="Historial enviado">
          <Fact name="Turnos enviados / omitidos" value={`${receipt.history.sent_turns ?? NA} / ${receipt.history.omitted_turns ?? NA}`} />
          <Fact name="Bytes enviados / omitidos" value={`${receipt.history.sent_bytes ?? NA} / ${receipt.history.omitted_bytes ?? NA}`} />
        </Section>
      )}
      {(limits.length > 0 || receipt.limits?.provider_managed) && (
        <Section title="Límites">
          {limits.map(([key, name]) => <Fact key={key} name={name} value={receipt.limits![key]} />)}
          {receipt.limits?.provider_managed && <Fact name="Límites de generación" value="Gestionados por el proveedor" />}
        </Section>
      )}
      {receipt.route && (
        <Section title="Ruta">
          <Fact name="Selección" value={ROUTE[String(receipt.route.mode)] ?? receipt.route.mode} />
          {receipt.route.company_engine_id !== null && receipt.route.company_engine_id !== undefined && (
            <Fact name="Destino" value={`engine:${String(receipt.route.company_engine_id)}`} />
          )}
          <Fact name="Modelo" value={receipt.route.model_effective || receipt.route.model || receipt.route.model_requested || receipt.route.model_id} />
          {Boolean(receipt.route.task) && <Fact name="Tarea" value={receipt.route.task} />}
          {Boolean(receipt.route.level || receipt.route.tier) && <Fact name="Nivel" value={receipt.route.level || receipt.route.tier} />}
          {list<string>(receipt.route.reason_codes).length > 0 && <Fact name="Motivos de la ruta" value={receipt.route.reason_codes!.join(", ")} />}
        </Section>
      )}
      {receipt.delivery && (
        <Section title="Entrega">
          <Fact name="Modo" value={receipt.delivery.mode === "streamed" ? "Progresiva, comprobada por fragmentos" : "Al completar las comprobaciones"} />
          {receipt.delivery.reason && <Fact name="Motivo" value={DELIVERY[receipt.delivery.reason] ?? receipt.delivery.reason} />}
          {list<{ attempt: number; reason: string }>(receipt.delivery.withdrawn).map((item, index) => (
            <Fact key={`withdrawn-${index}`} name="Texto retirado" value={`Intento ${item.attempt}: ${item.reason}`} />
          ))}
        </Section>
      )}
      {receipt.jev ? (
        <>
          <AgentReceipt receipt={receipt} />
          <Section title="Coste">
            <Fact name="Coste total" value={total?.cost ?? NA} />
            {(total?.cost === null || total?.cost === undefined) && present(total?.known_cost) && <Fact name="Subtotal conocido (incompleto)" value={total!.known_cost} />}
            {total?.currency && <Fact name="Moneda" value={total.currency} />}
          </Section>
        </>
      ) : (
        <>
          <Section title="Verificación">
            <Fact name="Estado" value={VERIFICATION[receipt.verification?.status ?? ""] ?? receipt.verification?.status ?? "No realizada"} />
            {list<string>(receipt.verification?.reason_codes).length > 0 && <Fact name="Motivos" value={receipt.verification!.reason_codes!.join(", ")} />}
            {judge?.signals && Object.entries(SIGNALS).map(([key, name]) => {
              const value = judge.signals?.[key]?.noul
              return typeof value === "number" && Number.isFinite(value) ? <Fact key={key} name={name} value={value} /> : null
            })}
            {judge && typeof judge.threshold === "number" && <Fact name="Umbral máximo de fallo admitido" value={Number((1 - judge.threshold).toFixed(10))} />}
          </Section>
          <section className="flex flex-col gap-1.5">
            <h4 className="text-xs font-semibold text-foreground">Llamadas · {calls.length}</h4>
            {calls.length > 0 && (
              <ol className="flex flex-col gap-2">
                {calls.map((call, index) => (
                  <li key={index}>
                    <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 text-[0.8125rem]">
                      <Fact
                        name={`Llamada ${index + 1}`}
                        value={[PURPOSE[call.purpose ?? ""] ?? call.purpose, CALL_STATUS[call.status ?? ""] ?? call.status, call.provider, call.model_effective || call.model].filter(Boolean).join(" · ")}
                      />
                      <Fact name="Coste" value={amount(call.cost, call.currency)} />
                      {call.duration_ms !== null && call.duration_ms !== undefined && <Fact name="Duración" value={`${call.duration_ms} ms`} />}
                    </dl>
                  </li>
                ))}
              </ol>
            )}
          </section>
          <Section title="Coste">
            {generation && <Fact name="Ruta efectiva" value={[generation.provider, generation.model_effective || generation.model].filter(Boolean).join(" / ")} />}
            {/* Zero only when the record lists its calls and there were none (e.g. blocked locally). */}
            <Fact
              name="Coste total"
              value={total?.cost !== null && total?.cost !== undefined ? amount(total.cost, total.currency) : Array.isArray(receipt.calls) && !calls.length ? "0 (sin llamadas)" : NA}
            />
            {(total?.cost === null || total?.cost === undefined) && present(total?.known_cost) && <Fact name="Subtotal conocido (incompleto)" value={amount(total!.known_cost, total!.currency)} />}
            {total && (
              <Fact
                name="Integridad del coste"
                value={({ estimated: "Estimado con las tarifas configuradas", incomplete: "Incompleto" } as Record<string, string>)[total.cost_status || total.status || ""]
                  || (total.complete === false ? "Incompleto" : NA)}
              />
            )}
            {total?.duration_ms !== null && total?.duration_ms !== undefined && <Fact name="Duración total" value={`${total.duration_ms} ms`} />}
          </Section>
        </>
      )}
    </div>
  )
}

const COST_ORIGIN: Record<string, string> = {
  provider_reported: "Informado por el proveedor", tariff_estimate: "Estimación con las tarifas configuradas",
  no_api_charge: "Sin cargo de API", configured_upper_bound_estimate: "Estimación máxima configurada", unknown: NA,
}

/** Jev consultation and the sequence of calls of an agent run (agent-chat.js renderReceipt). */
export function AgentReceipt({ receipt }: { receipt: ReceiptData }) {
  const calls = list<ReceiptCall>(receipt.calls)
  return (
    <div className="flex flex-col gap-3">
      <details className="group/jev">
        <summary className="cursor-pointer text-xs font-semibold text-foreground">Consulta y decisión de Jev</summary>
        <div className="mt-2"><JevFacts jev={(receipt.jev ?? {}) as Record<string, unknown>} /></div>
      </details>
      <details>
        <summary className="cursor-pointer text-xs font-semibold text-foreground">
          Secuencia de llamadas · {calls.length} {calls.length === 1 ? "llamada" : "llamadas"}
        </summary>
        <CallList calls={calls} />
      </details>
    </div>
  )
}

function CallList({ calls }: { calls: ReceiptCall[] }) {
  if (!calls.length) return <p className="mt-2 text-[0.8125rem] text-muted-foreground">No hay llamadas registradas.</p>
  return (
    <ol className="mt-2 flex flex-col gap-1">
      {calls.map((call, index) => {
        const noModel = call.purpose === "research" ? "Lectura sin modelo" : NA
        const route = call.route as Record<string, unknown> | string | undefined
        const fallback = call.fallback as Record<string, unknown> | boolean | undefined
        const protection = call.protection as { reused?: number; protected?: number } | undefined
        return (
          <li key={index}>
            <details>
              <summary className="cursor-pointer text-[0.8125rem] text-foreground">
                {call.sequence || index + 1}. {runLabel(call.purpose)} · {call.model_effective || noModel}
              </summary>
              <dl className="mt-1 mb-2 grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 pl-4 text-[0.8125rem]">
                <Fact name="Estado" value={runLabel(call.status)} />
                <Fact name="Proveedor" value={call.provider_name || call.provider} />
                <Fact name="Modelo solicitado" value={call.model_requested || call.model || noModel} />
                <Fact name="Modelo efectivo" value={call.model_effective || noModel} />
                {route && typeof route === "object" ? (
                  <>
                    <Fact name="Ruta" value={runLabel(route.mode)} />
                    {present(route.destination) && <Fact name="Destino" value={route.destination} />}
                    {present(route.connector) && <Fact name="Conector" value={route.connector} />}
                    {present(route.upstream_provider) && <Fact name="Proveedor de destino" value={route.upstream_provider} />}
                  </>
                ) : <Fact name="Ruta" value={route} />}
                <Fact
                  name="Fallback"
                  value={typeof fallback === "object" && fallback ? runLabel(fallback.status) : fallback === true ? "Utilizado" : fallback === false ? "No utilizado" : NA}
                />
                {typeof fallback === "object" && fallback && present(fallback.reason) && <Fact name="Motivo de fallback" value={fallback.reason} />}
                {present(call.started_at) && <Fact name="Inicio" value={timestamp(String(call.started_at))} />}
                <Fact name="Duración" value={present(call.duration_ms) ? `${call.duration_ms} ms` : NA} />
                <Fact name="Coste" value={amount(call.cost, call.currency)} />
                <Fact name="Origen del coste" value={COST_ORIGIN[call.cost_kind ?? ""] ?? NA} />
                {protection && typeof protection === "object" && (
                  <Fact
                    name="Protección del historial"
                    value={`${Number(protection.reused) || 0} reutilizados · ${Number(protection.protected) || 0} protegidos en esta llamada`}
                  />
                )}
              </dl>
              {Boolean(call.jev) && (
                <details className="mb-2 pl-4">
                  <summary className="cursor-pointer text-[0.8125rem]">Consulta Jev de esta llamada</summary>
                  <div className="mt-1"><JevFacts jev={call.jev as Record<string, unknown>} /></div>
                </details>
              )}
            </details>
          </li>
        )
      })}
    </ol>
  )
}

function JevFacts({ jev }: { jev: Record<string, unknown> }) {
  const decision = jev.decision
  const policy = (jev.policy ?? {}) as Record<string, unknown>
  const applied = jev.applied as Record<string, unknown> | undefined
  const signals = jev.signals as Record<string, unknown> | undefined
  return (
    <div className="flex flex-col gap-2">
      <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 text-[0.8125rem]">
        <Fact name="Estado de Jev" value={jev.status === "failed" ? "Falló" : runLabel(jev.status || "unknown")} />
        {present(jev.purpose) && <Fact name="Propósito" value={runLabel(jev.purpose)} />}
        <Fact name="Consulta" value={jev.consulted_at ? timestamp(String(jev.consulted_at)) : "No consta una consulta"} />
        {present(jev.completed_at) && <Fact name="Fin" value={timestamp(String(jev.completed_at))} />}
        {decision && typeof decision === "object"
          ? Object.entries({ category: "Categoría", task: "Tarea", difficulty: "Dificultad" }).map(([key, name]) =>
              present((decision as Record<string, unknown>)[key]) ? <Fact key={key} name={name} value={(decision as Record<string, unknown>)[key]} /> : null)
          : typeof decision === "string" && <Fact name="Decisión" value={decision} />}
        <Fact name="Motivos devueltos" value={list<string>(jev.reasons).join(" · ") || "Jev no ha proporcionado motivos textuales."} />
        <Fact name="Recomendaciones devueltas" value={list<string>(jev.recommendations).join(" · ") || "Jev no ha proporcionado recomendaciones textuales."} />
        <Fact name="Política aplicada" value={[policy.source, present(policy.revision) ? `revisión ${String(policy.revision)}` : null].filter(Boolean).join(" · ") || NA} />
        {present(policy.classification) && <Fact name="Clasificación exigida" value={policy.classification} />}
        {present(policy.threshold) && <Fact name="Umbral de la política" value={policy.threshold} />}
        {present(jev.effect) && <Fact name="Efecto sobre la ejecución" value={runLabel(jev.effect)} />}
        {applied && typeof applied === "object" && (
          <Fact name="Decisión aplicada por Regulay" value={[applied.sensitivity, applied.task, applied.difficulty].filter(present).join(" · ")} />
        )}
        {list<string>(jev.reason_codes).length > 0 && <Fact name="Motivos locales del efecto" value={list<string>(jev.reason_codes).join(" · ")} />}
      </dl>
      {signals && typeof signals === "object" && Object.keys(signals).length > 0 && (
        <details>
          <summary className="cursor-pointer text-[0.8125rem]">Señales estructuradas devueltas por Jev</summary>
          <pre className="mt-1 max-h-64 overflow-auto rounded-md bg-surface-2 p-2 text-xs">{JSON.stringify(signals, null, 2)}</pre>
        </details>
      )}
      <p className="text-xs text-muted-foreground">La decisión de enrutamiento se muestra en cada llamada. Una autorización local no es una aprobación de Jev.</p>
    </div>
  )
}
