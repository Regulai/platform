import { amount, list, present } from "@/lib/format"
import { runLabel } from "@/lib/labels"

import type { RunView } from "../state/model"
import { AgentReceipt } from "../turn/Receipt"
import type { ReceiptCall } from "../types"

/** Usage and cost on demand, from server receipts only; unknown is never zero.
 * Loaded the first time someone opens the details of a run. */
export default function Oversight({ view }: { view: RunView }) {
  const data = view.data
  const receipt = data?.receipt || data?.result?.receipt || {}
  const calls = list<ReceiptCall>(receipt.calls)
  const total = receipt.total ?? {}
  const models = [...new Set(calls.map((call) => call.model_effective).filter(Boolean))]
  const cost = amount(total.cost, total.currency)
  const estimated = calls.some((call) => ["tariff_estimate", "configured_upper_bound_estimate"].includes(String(call.cost_kind))) ? " · incluye estimación" : ""
  const jev = receipt.jev && typeof receipt.jev === "object" ? (receipt.jev as { status?: string }).status : undefined
  const rows: [string, string][] = [
    ["Seguridad local", runLabel(receipt.policy?.status)],
    ["Jev", jev === "failed" ? "Falló" : jev ? runLabel(jev) : "Sin registro"],
    ["Modelo efectivo", models.length > 1 ? `${models.length} modelos · ${calls.length} llamadas` : String(models[0] || "Sin dato efectivo")],
    ["Coste", cost === "No disponible" && present(total.known_cost) ? `${amount(total.known_cost, total.currency)} conocido${estimated} · total no disponible` : cost + (cost === "No disponible" ? "" : estimated)],
  ]
  return (
    <div className="mt-2 flex flex-col gap-3 rounded-xl bg-surface px-4 py-3">
      <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 text-[0.8125rem]">
        {rows.map(([name, value]) => (
          <div key={name} className="contents">
            <dt className="text-muted-foreground">{name}</dt>
            <dd className="tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
      {data?.infrastructure && <p className="text-xs text-muted-foreground">El coste mostrado corresponde a APIs. El coste del sandbox y del tráfico no está disponible.</p>}
      <AgentReceipt receipt={receipt} />
      {list<string>(receipt.policy?.reason_codes).length > 0 && (
        <details>
          <summary className="cursor-pointer text-xs font-semibold">Decisión de la política local</summary>
          <p className="mt-1 text-xs text-muted-foreground">{receipt.policy!.reason_codes!.join(" · ")}</p>
        </details>
      )}
    </div>
  )
}
