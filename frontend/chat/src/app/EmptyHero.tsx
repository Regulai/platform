import { InfoIcon } from "lucide-react"

import { useSession } from "./session-context"

/** A new conversation: one line of invitation; the composer below is the focus. */
export function EmptyHero() {
  const boot = useSession().boot
  return (
    <div className="flex min-h-0 flex-1 flex-col justify-end px-4 pb-5">
      <div className="mx-auto flex w-full max-w-(--read) flex-col gap-4">
        <h2 className="text-[1.625rem] leading-tight font-semibold tracking-tight text-balance sm:text-[1.75rem]">¿En qué puedo ayudarte?</h2>
        {boot.setup.missing && (
          <div role="status" className="flex items-start gap-3 rounded-xl bg-warning-soft px-4 py-3 text-sm text-foreground">
            <InfoIcon className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
            <p>
              <strong className="font-semibold">Falta configurar la IA de esta cuenta.</strong>{" "}
              {boot.setup.can_manage ? (
                <>Guarda una clave y activa el chat básico en <a className="font-medium text-brand-strong underline underline-offset-2" href={boot.urls.ai_connections}>Conexiones IA</a>.</>
              ) : (
                "Pide al administrador de tu cuenta que active una política en Conexiones IA."
              )}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
