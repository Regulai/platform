import { CloudIcon, RotateCwIcon } from "lucide-react"
import { useState } from "react"

import { Button } from "@/components/ui/button"
import { present, timestamp } from "@/lib/format"

import { useSession } from "../app/session-context"
import { postJSON } from "../transport/http"
import type { ExportProposal as Proposal, RunData } from "../types"

const DOWNLOAD = /^\/chat\/agent\/artifacts\/[0-9a-f-]+\/download\/$/
const STATUS: Record<string, string> = {
  pending: "Esperando aprobación", approved: "Aprobado", rejected: "Rechazado", intent: "Guardando; resultado pendiente",
  uncertain: "Resultado por confirmar", completed: "Guardado confirmado",
}

/** An external write needs an explicit decision; it stays visible while it does. */
export function ExportProposal({ proposal, run }: { proposal: Proposal; run: RunData }) {
  const session = useSession()
  const [busy, setBusy] = useState(false)
  const controller = session.runController(run.id)
  const decide = async (decision: "approve" | "reject") => {
    if (!proposal.decision_url) return
    setBusy(true)
    try {
      await postJSON(proposal.decision_url, { binding: proposal.binding, decision })
      await controller?.reload()
    } catch {
      controller?.note("La propuesta ha caducado o sus permisos han cambiado. Actualiza para comprobar el estado.", "error")
    } finally {
      setBusy(false)
    }
  }
  const recover = async () => {
    setBusy(true)
    try {
      await postJSON(`/chat/agent/runs/${encodeURIComponent(run.id)}/recover-export/`)
      controller?.stop()
      controller?.start()
    } catch {
      controller?.note("No se pudo recuperar el resultado. Comprueba los permisos y la aprobación.", "error")
    } finally {
      setBusy(false)
    }
  }
  const pending = proposal.status === "pending" && run.status === "active" && Date.parse(proposal.expires_at ?? "") > Date.now()
  const facts: [string, unknown][] = [
    ["Cuenta", proposal.account], ["Carpeta", proposal.folder], ["Nombre", proposal.name], ["Revisión", proposal.revision],
    ["Efecto", "Crear un archivo nuevo"], ["Contenido", present(proposal.bytes) ? `${proposal.bytes} bytes` : null],
    ["SHA-256 del contenido", proposal.sha256], ["Estado", STATUS[proposal.status] ?? proposal.status], ["Caduca", timestamp(proposal.expires_at)],
  ]
  return (
    <section className="flex flex-col gap-3 rounded-xl bg-surface p-4 ring-1 ring-border" aria-label="Guardar revisión en Google Drive">
      <h3 className="flex items-center gap-2 text-sm font-semibold"><CloudIcon className="size-4 text-muted-foreground" aria-hidden />Guardar revisión en Google Drive</h3>
      <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1 text-[0.8125rem]">
        {facts.filter(([, value]) => present(value)).map(([name, value]) => (
          <div key={name} className="contents">
            <dt className="text-muted-foreground">{name}</dt>
            <dd className="min-w-0 break-all">{String(value)}</dd>
          </div>
        ))}
      </dl>
      {proposal.preview_url && DOWNLOAD.test(proposal.preview_url) && (
        <a className="w-fit text-[0.8125rem] text-brand-strong underline-offset-2 hover:underline" href={proposal.preview_url}>Revisar el contenido exacto antes de aprobar</a>
      )}
      {(pending || (proposal.status === "uncertain" && run.status === "interrupted")) && (
        <div className="flex flex-wrap gap-2">
          {pending && (
            <>
              <Button size="sm" disabled={busy} onClick={() => decide("approve")}>Aprobar esta exportación</Button>
              <Button size="sm" variant="outline" disabled={busy} onClick={() => decide("reject")}>Rechazar</Button>
            </>
          )}
          {proposal.status === "uncertain" && run.status === "interrupted" && (
            <Button size="sm" variant="outline" disabled={busy} onClick={recover}><RotateCwIcon aria-hidden />Reconciliar el resultado de la exportación</Button>
          )}
        </div>
      )}
    </section>
  )
}
