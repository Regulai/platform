import { CheckIcon, ExternalLinkIcon, RotateCwIcon, SearchIcon, XIcon } from "lucide-react"
import { useEffect, useId, useMemo, useRef, useState, type ReactNode, type RefObject } from "react"

import { Button } from "@/components/ui/button"
import { Popover, PopoverContent, PopoverTitle } from "@/components/ui/popover"
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { useMediaQuery } from "@/lib/hooks"
import { cn } from "@/lib/utils"

import { useSession } from "../app/session-context"
import { displayName, summary, type SkillsApi } from "./use-skills"

/* The manual way to choose skills for the next agent message: `/` at the start
 * of an empty message or the button. A searchable listbox (arrows, Enter,
 * Escape) inside a popover anchored to the composer; on a phone, where neither
 * side of the composer has room for it, a bottom sheet with the same content. */

/** Closing by Escape or the close button returns focus to where the picker came from;
 * choosing returns it to the message; a click elsewhere leaves focus where it lands. */
export function SkillPicker({ skills, open, onClose, onChosen, anchor }: {
  skills: SkillsApi
  open: boolean
  onClose: (returnFocus: boolean) => void
  onChosen: () => void
  anchor: RefObject<HTMLElement | null>
}) {
  const session = useSession()
  const [query, setQuery] = useState("")
  const [active, setActive] = useState(-1)
  const [status, setStatus] = useState("")
  const listId = useId()
  const helpId = useId()
  const search = useRef<HTMLInputElement>(null)
  // Opening (button or a literal "/") is the only moment the catalogue is requested.
  useEffect(() => {
    if (!open) return
    setQuery("")
    setActive(-1)
    setStatus("")
    void skills.load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])
  const matches = useMemo(() => {
    const value = query.toLocaleLowerCase("es")
    return skills.rows.filter((row) => `${displayName(row)} ${row.alias ?? ""} ${summary(row)}`.toLocaleLowerCase("es").includes(value))
  }, [skills.rows, query])

  const choose = (index: number) => {
    const row = matches[index]
    if (!row) return
    const refused = skills.toggle(row)
    if (refused) {
      setStatus(refused)
      return
    }
    setStatus("")
    onClose(false)
    onChosen()
  }

  const statusText = status || (skills.loading ? "Cargando tus skills…" : skills.error ? skills.error : skills.loaded
    ? !skills.rows.length ? "Aún no tienes skills instaladas. Encuentra una en la biblioteca."
      : !matches.length ? "No hay skills con ese nombre. Prueba otra búsqueda." : "Se usará en el próximo mensaje."
    : "")

  const sheet = useMediaQuery("(max-width: 639px)")
  const onOpenChange = (next: boolean, details: { reason: string }) => {
    if (!next) onClose(details.reason === "escape-key" || details.reason === "close-press")
  }
  const title = "Skills para el próximo mensaje"
  // Only the list scrolls: title, search, automatic selection and the library link stay in view.
  const frame = "gap-2 overflow-hidden *:shrink-0"

  if (sheet) {
    return (
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent side="bottom" showCloseButton={false} initialFocus={search} finalFocus={false}
          className={cn(frame, "max-h-[85dvh] rounded-t-2xl p-3 pb-[max(0.75rem,env(safe-area-inset-bottom))]")}>
          {body(<SheetTitle className="flex-1 text-[0.8125rem] font-semibold">{title}</SheetTitle>)}
        </SheetContent>
      </Sheet>
    )
  }
  return (
    <Popover open={open} onOpenChange={onOpenChange}>
      <PopoverContent anchor={anchor} side="top" align="start" sideOffset={8} initialFocus={search} finalFocus={false}
        className={cn(frame, "max-h-(--available-height) w-[min(26rem,calc(100vw-1.5rem))] p-2")}>
        {body(<PopoverTitle className="flex-1 text-[0.8125rem] font-semibold">{title}</PopoverTitle>)}
      </PopoverContent>
    </Popover>
  )

  function body(heading: ReactNode) {
    return (
      <>
        <div className="flex items-center gap-2 px-1.5 pt-1">
          {heading}
          <Button variant="ghost" size="icon-sm" className="text-muted-foreground" aria-label="Cerrar selector de skills" onClick={() => onClose(true)}>
            <XIcon />
          </Button>
        </div>
        <label className="flex h-9 items-center gap-2 rounded-lg bg-surface-2 px-2.5 text-sm pointer-coarse:h-11">
          <SearchIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="sr-only">Buscar en tus skills</span>
          <input
            ref={search}
            type="search"
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={active >= 0 && matches[active] ? `${listId}-${matches[active]!.id}` : undefined}
            placeholder="Buscar una skill"
            autoComplete="off"
            value={query}
            onChange={(event) => { setQuery(event.target.value); setActive(-1) }}
            onKeyDown={(event) => {
              if ((event.key === "ArrowDown" || event.key === "ArrowUp") && matches.length) {
                event.preventDefault()
                const step = event.key === "ArrowDown" ? 1 : -1
                setActive((current) => (current < 0 ? (step > 0 ? 0 : matches.length - 1) : (current + step + matches.length) % matches.length))
              } else if (event.key === "Enter") {
                event.preventDefault()
                if (active >= 0) choose(active)
              }
            }}
            className="h-full min-w-0 flex-1 bg-transparent outline-none placeholder:text-subtle-foreground [&::-webkit-search-cancel-button]:hidden"
          />
        </label>
        <div id={listId} role="listbox" aria-label="Skills instaladas" aria-multiselectable="true" aria-busy={skills.loading}
          className="rg-scroll-shadows flex max-h-60 min-h-14 flex-col gap-px overflow-y-auto overscroll-contain shrink!">
          {matches.map((row, index) => {
            const selected = skills.selected.includes(row.id)
            const usable = skills.ready(row)
            const state = row.enabled === false ? "Deshabilitada" : !row.availability?.available ? "Requiere configuración" : !skills.runtime ? "Ejecución desactivada" : ""
            const needs = skills.requirements(row)
            return (
              <div
                key={row.id}
                id={`${listId}-${row.id}`}
                role="option"
                aria-selected={selected}
                aria-disabled={!usable}
                tabIndex={-1}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => choose(index)}
                onMouseEnter={() => setActive(index)}
                className={cn(
                  "flex cursor-default items-start gap-2.5 rounded-md px-2 py-2 transition-colors pointer-coarse:min-h-11",
                  index === active && "bg-surface-2",
                  !usable && "opacity-60",
                )}
              >
                <span className={cn("mt-0.5 flex size-4 shrink-0 items-center justify-center rounded border", selected ? "border-brand bg-brand text-white" : "border-input")} aria-hidden>
                  {selected && <CheckIcon className="size-3" strokeWidth={3} />}
                </span>
                <span className="min-w-0">
                  <span className="block truncate text-sm font-medium">{displayName(row)}</span>
                  <span className="line-clamp-2 text-xs text-muted-foreground">
                    {usable ? summary(row) : `${state}${needs ? `: ${needs}` : ""}`}
                  </span>
                </span>
              </div>
            )
          })}
        </div>
        <p role="status" aria-live="polite" className="px-1.5 text-xs text-muted-foreground">{statusText}</p>
        {skills.error && (
          <Button size="sm" variant="outline" className="mx-1.5 w-fit" onClick={() => void skills.load()}>
            <RotateCwIcon aria-hidden />Volver a cargar
          </Button>
        )}
        <div className="flex flex-col gap-1 rounded-lg bg-surface px-2.5 py-2">
          <label className="flex min-h-9 cursor-pointer items-center justify-between gap-3 text-[0.8125rem] font-medium pointer-coarse:min-h-11">
            Selección automática
            <Switch checked={skills.auto} disabled={!skills.runtime} onCheckedChange={(value) => void skills.setAuto(value)} aria-describedby={helpId} />
          </label>
          <p id={helpId} className="text-xs text-muted-foreground">
            {!skills.runtime ? "La ejecución de skills está desactivada. Puedes gestionar tus instalaciones en la biblioteca."
              : skills.auto ? "El agente puede cargar las instrucciones que necesite para tu tarea."
              : "La selección automática está desactivada en este chat. Puedes elegir una skill con /."}
          </p>
        </div>
        <a
          href={session.boot.urls.skills_library}
          onClick={skills.leaving}
          className="inline-flex min-h-9 w-fit items-center gap-1.5 rounded-md px-1.5 text-[0.8125rem] font-medium text-brand-strong underline-offset-2 hover:underline pointer-coarse:min-h-11"
        >
          Gestionar skills
          <ExternalLinkIcon className="size-3.5" aria-hidden />
        </a>
      </>
    )
  }
}
