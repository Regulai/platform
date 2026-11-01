import { CloudIcon, FileSpreadsheetIcon, SearchIcon } from "lucide-react"
import { useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { Popover, PopoverContent, PopoverTitle, PopoverTrigger } from "@/components/ui/popover"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

import { useSession } from "../app/session-context"
import { postJSON } from "../transport/http"

/** A CSV/XLSX from the authorized Drive folder, as the next agent message's input. */
export function DrivePicker({ onChosen }: { onChosen: () => void }) {
  const session = useSession()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [state, setState] = useState<{ status: "idle" | "loading" | "ready" | "error"; documents: { reference: string; label: string }[] }>({ status: "idle", documents: [] })
  const input = useRef<HTMLInputElement>(null)

  const search = async () => {
    setState({ status: "loading", documents: [] })
    session.setContext(null)
    try {
      const data = await postJSON<{ documents?: { reference: string; label: string }[] }>(session.boot.urls.documents_search, { query })
      setState({ status: "ready", documents: Array.isArray(data.documents) ? data.documents : [] })
    } catch {
      setState({ status: "error", documents: [] })
    }
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger render={<PopoverTrigger render={<Button variant="ghost" size="icon" className="size-8 text-muted-foreground pointer-coarse:size-11" aria-label="Usar un archivo de Google Drive" />} />}>
          <CloudIcon />
        </TooltipTrigger>
        <TooltipContent>Archivo de Google Drive</TooltipContent>
      </Tooltip>
      <PopoverContent side="top" align="start" sideOffset={10} initialFocus={input} className="w-[min(22rem,calc(100vw-1.5rem))] gap-2 p-2.5">
        <PopoverTitle className="text-[0.8125rem] font-semibold">Nombre del CSV o XLSX en la carpeta autorizada</PopoverTitle>
        <form className="flex gap-2" onSubmit={(event) => { event.preventDefault(); void search() }}>
          <input ref={input} value={query} maxLength={160} autoComplete="off" onChange={(event) => setQuery(event.target.value)}
            aria-label="Nombre del archivo" className="h-9 min-w-0 flex-1 rounded-md bg-surface-2 px-2.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/50 pointer-coarse:h-11" />
          <Button type="submit" size="sm" variant="outline" className="h-9" disabled={state.status === "loading"}><SearchIcon aria-hidden />Buscar</Button>
        </form>
        <div role="status" className="flex flex-col gap-1 text-[0.8125rem]">
          {state.status === "ready" && !state.documents.length && <p className="text-muted-foreground">No hay archivos compatibles en la carpeta autorizada.</p>}
          {state.status === "error" && <p className="text-muted-foreground">Conector no disponible. Requiere una cuenta autorizada por el administrador.</p>}
          {state.documents.map((document) => (
            <button key={document.reference} type="button"
              className="flex min-h-9 items-center gap-2 rounded-md px-2 text-left transition-colors hover:bg-surface-2 focus-visible:outline-2 focus-visible:outline-ring"
              onClick={() => {
                session.setContext({ kind: "drive", reference: document.reference, label: document.label })
                setOpen(false)
                setState({ status: "idle", documents: [] })
                onChosen()
              }}>
              <FileSpreadsheetIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <span className="truncate">{document.label}</span>
            </button>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  )
}
