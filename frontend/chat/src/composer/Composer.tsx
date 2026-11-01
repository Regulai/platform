import {
  ArrowUpIcon, ChevronDownIcon, CloudIcon, PaperclipIcon, PencilIcon, SparklesIcon, SquareIcon, SquareSlashIcon, TriangleAlertIcon, XIcon,
} from "lucide-react"
import { Radio } from "@base-ui/react/radio"
import { RadioGroup } from "@base-ui/react/radio-group"
import { AnimatePresence, m } from "motion/react"
import { lazy, Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { InputGroup, InputGroupAddon, InputGroupTextarea } from "@/components/ui/input-group"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { fileSize } from "@/lib/format"
import { cn } from "@/lib/utils"

import { useChat, useSession } from "../app/session-context"
import { isLiveRun } from "../state/model"
import { fileIcon } from "../turn/parts"
import type { Mode } from "../types"
import { ModelMenu } from "./ModelMenu"
import { useSkills } from "./use-skills"
import { fileProblem } from "./validate"

// Loaded on first use: the skills picker when it opens, the Drive picker when Drive is configured.
const SkillPicker = lazy(() => import("./SkillPicker").then((module) => ({ default: module.SkillPicker })))
const DrivePicker = lazy(() => import("./DrivePicker").then((module) => ({ default: module.DrivePicker })))

/* One surface: write, attach, `/` and send/stop. Enter sends unless an IME is
 * composing; Shift+Enter is a new line. One file per message, checked against
 * the server's types and size before upload (the server still validates). */

export function Composer() {
  const session = useSession()
  const boot = session.boot
  const mode = useChat((state) => state.mode)
  const busy = useChat((state) => state.busy)
  const sending = useChat((state) => state.sending)
  const empty = useChat((state) => state.turns.length === 0)
  const context = useChat((state) => state.context)
  const pendingExport = useChat((state) => state.pendingExport)
  const applyTo = useChat((state) => {
    if (boot.composer.professional || state.context) return null
    const latest = state.latestRun ? state.runs[state.latestRun] : null
    const revision = latest?.data?.current_revision
    return revision && latest && !isLiveRun(latest.run.status) ? revision : null
  })
  const [text, setText] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [problem, setProblem] = useState("")
  const [dragging, setDragging] = useState(false)
  const [profile, setProfile] = useState(boot.composer.inference_profiles[0]?.value ?? "")
  // `used`: the picker's code loads the first time it opens and then stays mounted.
  const [picker, setPicker] = useState({ open: false, fromSlash: false, used: false })
  const textarea = useRef<HTMLTextAreaElement>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const surface = useRef<HTMLDivElement>(null)
  const skillButton = useRef<HTMLButtonElement>(null)
  const draft = useRef(text)
  draft.current = text

  const setMode = useCallback((next: Mode) => session.setMode(next), [session])
  const skills = useSkills(session, mode, setMode, setText)
  const agent = mode === "agent"
  const accept = boot.composer.accept[mode]
  const canSend = !busy.owner && !sending && Boolean(text.trim() || file)
  const showModes = boot.composer.modes.length > 1 && empty
  const attachDisabled = sending

  useEffect(() => {
    session.focusComposer = () => textarea.current?.focus()
    session.composerDraft = () => draft.current
    session.restoreComposer = ({ prompt, file: restored }) => {
      setText((current) => (current.trim() ? `${current}\n\n${prompt}` : prompt))
      if (restored) setFile((current) => current ?? restored)
      window.requestAnimationFrame(() => textarea.current?.focus())
    }
    return () => {
      session.focusComposer = null
      session.composerDraft = null
      session.restoreComposer = null
    }
  }, [session])

  // A file that does not fit the new mode is dropped with a note, as before.
  useEffect(() => {
    if (file && fileProblem(file, mode, boot.composer)) {
      setFile(null)
      setProblem(`«${file.name}» no se admite en este modo y se ha quitado.`)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode])

  // Fine pointers start typing right away, unless a request is being rejoined.
  useEffect(() => {
    if (window.matchMedia?.("(pointer: fine)").matches && !session.store.get().busy.owner) textarea.current?.focus({ preventScroll: true })
  }, [session])

  useLayoutEffect(() => {
    const node = textarea.current
    if (!node) return
    node.style.height = "auto"
    node.style.height = `${Math.min(node.scrollHeight, Math.round(window.innerHeight * 0.4))}px`
  }, [text])

  // A file dropped anywhere else must not navigate away or attach by accident.
  useEffect(() => {
    const guard = (event: DragEvent) => {
      if (!event.dataTransfer?.types?.includes("Files")) return
      if (surface.current?.contains(event.target as Node)) return
      event.preventDefault()
      if (event.type === "dragover") event.dataTransfer.dropEffect = "none"
    }
    window.addEventListener("dragover", guard)
    window.addEventListener("drop", guard)
    return () => {
      window.removeEventListener("dragover", guard)
      window.removeEventListener("drop", guard)
    }
  }, [])

  const choose = useCallback((next: File | null, extra = 0) => {
    if (!next) return
    const issue = fileProblem(next, mode, boot.composer)
    if (issue) {
      setProblem(issue)
      return
    }
    setFile(next)
    setProblem(extra ? "Solo se envía un archivo por mensaje: se ha usado el primero." : "")
  }, [boot.composer, mode])

  const submit = () => {
    if (!canSend) return
    const sent = session.send({ prompt: text, file, mode, inferenceProfile: agent && profile ? profile : undefined })
    if (!sent) return
    setText("")
    setFile(null)
    setProblem("")
    skills.setNotice("")
  }

  const contextChip = context?.kind === "drive"
    ? { icon: CloudIcon, text: `Archivo de Drive: ${context.label}`, clear: () => session.setContext(null) }
    : context?.kind === "revision" && boot.composer.professional
      ? { icon: PencilIcon, text: `Editando «${context.title}», revisión ${context.artifact.revision}`, clear: () => session.setContext(null) }
      : applyTo
        ? { icon: PencilIcon, text: `Los cambios se aplicarán a «${applyTo.preview?.title || "Entregable"}», revisión ${applyTo.revision}`, clear: null }
        : pendingExport
          ? { icon: CloudIcon, text: "Exportación preparada para el próximo mensaje", clear: null }
          : null
  const hasTop = Boolean(file || problem || (agent && skills.chips.length) || (agent && contextChip) || (agent && skills.notice))

  return (
    <div className="flex flex-col gap-2">
      <form
        className="relative"
        onSubmit={(event) => { event.preventDefault(); submit() }}
        aria-label="Escribir un mensaje"
      >
        <input
          ref={fileInput}
          type="file"
          className="sr-only"
          tabIndex={-1}
          aria-hidden
          accept={accept.join(",")}
          onChange={(event) => {
            const files = event.target.files
            choose(files?.[0] ?? null, Math.max(0, (files?.length ?? 0) - 1))
            event.target.value = ""
          }}
        />
        <div
          ref={surface}
          onDragEnter={(event) => {
            if (!event.dataTransfer.types.includes("Files") || attachDisabled) return
            event.preventDefault()
            setDragging(true)
          }}
          onDragOver={(event) => {
            if (!event.dataTransfer.types.includes("Files")) return
            event.preventDefault()
            event.dataTransfer.dropEffect = attachDisabled ? "none" : "copy"
          }}
          onDragLeave={(event) => {
            if (!surface.current?.contains(event.relatedTarget as Node)) setDragging(false)
          }}
          onDrop={(event) => {
            if (!event.dataTransfer.types.includes("Files")) return
            event.preventDefault()
            setDragging(false)
            if (attachDisabled) return
            const files = event.dataTransfer.files
            choose(files[0] ?? null, Math.max(0, files.length - 1))
            textarea.current?.focus()
          }}
        >
          <InputGroup
            className={cn(
              "h-auto rounded-2xl border-input bg-background shadow-[0_1px_2px_rgb(16_24_40/0.05)] transition-[border-color,box-shadow] duration-150",
              "has-[[data-slot=input-group-control]:focus-visible]:border-[#98a2b3] has-[[data-slot=input-group-control]:focus-visible]:ring-3 has-[[data-slot=input-group-control]:focus-visible]:ring-foreground/[0.06]",
              dragging && "border-brand border-dashed ring-3 ring-brand/12",
            )}
            data-dragging={dragging || undefined}
          >
            {hasTop && (
              <InputGroupAddon align="block-start" className="flex-wrap gap-2 px-3 pt-3 pb-0">
                <AnimatePresence initial={false}>
                  {file && (
                    <m.div key="file" initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.96, transition: { duration: 0.12 } }}
                      className="flex max-w-full min-w-0 items-center gap-2 rounded-xl bg-surface py-1.5 pr-1 pl-2 ring-1 ring-border" data-slot="selected-file">
                      <FileChip file={file} />
                      <Button type="button" variant="ghost" size="icon-xs" className="text-muted-foreground pointer-coarse:size-10" aria-label={`Quitar ${file.name}`}
                        onClick={() => { setFile(null); textarea.current?.focus() }}>
                        <XIcon />
                      </Button>
                    </m.div>
                  )}
                  {agent && skills.chips.map((chip) => (
                    <m.span key={chip.id} initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.96, transition: { duration: 0.12 } }}
                      className="inline-flex max-w-full items-center gap-1 rounded-full bg-brand-soft py-1 pr-1 pl-2.5 text-xs font-medium text-brand-strong">
                      <SparklesIcon className="size-3.5 shrink-0" aria-hidden />
                      <span className="truncate">{chip.name}</span>
                      <button type="button" className="flex size-5 items-center justify-center rounded-full hover:bg-brand/10 focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:size-8"
                        aria-label={`Quitar skill ${chip.name} del próximo mensaje`} onClick={() => skills.remove(chip.id)}>
                        <XIcon className="size-3" aria-hidden />
                      </button>
                    </m.span>
                  ))}
                  {agent && contextChip && (
                    <m.span key="context" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                      className="inline-flex max-w-full items-center gap-1.5 rounded-full bg-surface-2 py-1 pr-1 pl-2.5 text-xs text-muted-foreground">
                      <contextChip.icon className="size-3.5 shrink-0" aria-hidden />
                      <span className="truncate">{contextChip.text}</span>
                      {contextChip.clear && (
                        <button type="button" className="flex size-5 items-center justify-center rounded-full hover:bg-surface-3 focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:size-8"
                          aria-label="Quitar selección" onClick={contextChip.clear}>
                          <XIcon className="size-3" aria-hidden />
                        </button>
                      )}
                    </m.span>
                  )}
                </AnimatePresence>
                {(problem || (agent && skills.notice)) && (
                  <p className="flex w-full items-start gap-1.5 text-xs text-warning" role="status">
                    <TriangleAlertIcon className="mt-px size-3.5 shrink-0" aria-hidden />
                    {problem || skills.notice}
                  </p>
                )}
              </InputGroupAddon>
            )}
            <label htmlFor="regulai-prompt" className="sr-only">Mensaje</label>
            <InputGroupTextarea
              id="regulai-prompt"
              ref={textarea}
              rows={1}
              value={text}
              placeholder={boot.composer.placeholders[mode]}
              autoComplete="off"
              spellCheck
              className="max-h-[40vh] min-h-12 px-4 pt-3.5 pb-2 text-[0.9375rem] leading-relaxed placeholder:text-placeholder [field-sizing:fixed] md:text-[0.9375rem]"
              onChange={(event) => {
                const value = event.target.value
                setText(value)
                const native = event.nativeEvent as InputEvent
                if (agent && skills.enabled && skills.runtime && !native.isComposing && value === "/" && event.target.selectionStart === 1 && event.target.selectionEnd === 1) {
                  setPicker({ open: true, fromSlash: true, used: true })
                }
              }}
              onKeyDown={(event) => {
                if (event.key !== "Enter" || event.shiftKey || event.nativeEvent.isComposing || event.keyCode === 229) return
                event.preventDefault()
                submit()
              }}
            />
            <InputGroupAddon align="block-end" className="gap-1 px-2 pt-1 pb-2">
              <Tooltip>
                <TooltipTrigger render={<Button type="button" variant="ghost" size="icon" className="size-8 text-muted-foreground pointer-coarse:size-11" aria-label="Adjuntar archivo" disabled={attachDisabled} onClick={() => fileInput.current?.click()} />}>
                  <PaperclipIcon />
                </TooltipTrigger>
                <TooltipContent>Adjuntar archivo</TooltipContent>
              </Tooltip>
              {agent && skills.enabled && (
                <Tooltip>
                  <TooltipTrigger render={
                    <Button ref={skillButton} type="button" variant="ghost" size="icon" disabled={!skills.runtime}
                      className="size-8 text-muted-foreground aria-expanded:bg-surface-2 aria-expanded:text-foreground pointer-coarse:size-11"
                      aria-label="Usar una skill (/)" aria-haspopup="dialog" aria-expanded={picker.open}
                      onClick={() => setPicker((current) => ({ open: !current.open, fromSlash: false, used: true }))} />
                  }>
                    <SquareSlashIcon />
                  </TooltipTrigger>
                  <TooltipContent>{skills.runtime ? "Usar una skill" : "La ejecución de skills está desactivada"}</TooltipContent>
                </Tooltip>
              )}
              {agent && boot.composer.drive && (
                <Suspense fallback={<span className="size-8 shrink-0 pointer-coarse:size-11" aria-hidden />}>
                  <DrivePicker onChosen={() => textarea.current?.focus()} />
                </Suspense>
              )}
              {showModes && <ModeToggle mode={mode} onChange={setMode} />}
              {agent && boot.composer.inference_profiles.length > 1 && (
                <ProfileMenu value={profile} onChange={setProfile} />
              )}
              <div className="ml-auto flex min-w-0 items-center gap-1">
                {busy.owner === "agent" && busy.hint && <span className="hidden truncate text-xs text-muted-foreground sm:inline" role="status">{busy.hint}</span>}
                <ModelMenu />
                <SendButton canSend={canSend} stoppable={Boolean(busy.owner && busy.stoppable)} busy={Boolean(busy.owner) || sending} onStop={() => session.stop()} />
              </div>
            </InputGroupAddon>
          </InputGroup>
          {dragging && (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-2xl bg-brand-soft/70 text-sm font-medium text-brand-strong" aria-hidden>
              Suelta para adjuntar
            </div>
          )}
        </div>
      </form>
      {skills.enabled && picker.used && (
        <Suspense fallback={null}>
          <SkillPicker
            skills={skills}
            open={picker.open}
            onClose={(returnFocus) => {
              const target = picker.fromSlash ? textarea.current : skillButton.current
              setPicker({ open: false, fromSlash: false, used: true })
              if (returnFocus) window.requestAnimationFrame(() => target?.focus())
            }}
            onChosen={() => {
              if (picker.fromSlash && draft.current === "/") setText("")
              window.requestAnimationFrame(() => textarea.current?.focus())
            }}
            anchor={surface}
          />
        </Suspense>
      )}
      {empty && agent && boot.composer.suggestions.length > 0 && (
        <div className="flex flex-wrap gap-2 px-1" aria-label="Sugerencias">
          {boot.composer.suggestions.map((suggestion) => (
            <button key={suggestion.label} type="button"
              className="rounded-full px-3 py-1.5 text-[0.8125rem] text-muted-foreground ring-1 ring-border transition-colors hover:bg-surface-2 hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:min-h-11"
              onClick={() => {
                setText(suggestion.text)
                window.requestAnimationFrame(() => {
                  const node = textarea.current
                  node?.focus()
                  node?.setSelectionRange(suggestion.text.length, suggestion.text.length)
                })
              }}>
              {suggestion.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function FileChip({ file }: { file: File }) {
  const Icon = fileIcon(file.name)
  return (
    <>
      <span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted-foreground"><Icon className="size-3.5" aria-hidden /></span>
      <span className="min-w-0 leading-tight">
        <span className="block max-w-[14rem] truncate text-[0.8125rem] font-medium">{file.name}</span>
        <span className="block text-xs text-subtle-foreground tabular-nums">{fileSize(file.size)}</span>
      </span>
    </>
  )
}

function SendButton({ canSend, stoppable, busy, onStop }: { canSend: boolean; stoppable: boolean; busy: boolean; onStop: () => void }) {
  return (
    <span className="relative flex size-8 shrink-0 items-center justify-center pointer-coarse:size-11">
      <AnimatePresence initial={false} mode="popLayout">
        {stoppable ? (
          <m.span key="stop" initial={{ opacity: 0, scale: 0.85 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.85 }} transition={{ duration: 0.12 }}>
            <Button type="button" size="icon" className="size-8 rounded-full bg-foreground text-background hover:bg-foreground/85 pointer-coarse:size-11" aria-label="Detener respuesta" onClick={onStop}>
              <SquareIcon className="size-3 fill-current" />
            </Button>
          </m.span>
        ) : (
          <m.span key="send" initial={{ opacity: 0, scale: 0.85 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.85 }} transition={{ duration: 0.12 }}>
            <Button type="submit" size="icon" disabled={!canSend} aria-label="Enviar"
              className={cn("size-8 rounded-full pointer-coarse:size-11", !canSend && "bg-surface-3 text-subtle-foreground opacity-100", busy && "cursor-progress")}>
              <ArrowUpIcon className="size-4" strokeWidth={2.25} />
            </Button>
          </m.span>
        )}
      </AnimatePresence>
    </span>
  )
}

function ModeToggle({ mode, onChange }: { mode: Mode; onChange: (mode: Mode) => void }) {
  const item = "flex h-7 items-center gap-1 rounded-md px-2.5 text-[0.8125rem] text-muted-foreground outline-none transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 data-[checked]:bg-background data-[checked]:text-foreground data-[checked]:shadow-xs pointer-coarse:h-10"
  return (
    <RadioGroup
      value={mode}
      onValueChange={(value) => { if (value === "chat" || value === "agent") onChange(value) }}
      aria-label="Modo de la conversación"
      className="ml-1 flex h-8 items-center rounded-lg bg-surface-2 p-0.5 pointer-coarse:h-11"
    >
      <Radio.Root value="chat" nativeButton render={<button type="button" />} className={item}>Chat</Radio.Root>
      <Radio.Root value="agent" nativeButton render={<button type="button" />} className={item}>
        <SparklesIcon className="size-3.5" aria-hidden />
        Agente
      </Radio.Root>
    </RadioGroup>
  )
}

function ProfileMenu({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const profiles = useSession().boot.composer.inference_profiles
  const current = profiles.find((item) => item.value === value) ?? profiles[0]
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="flex h-8 items-center gap-1 rounded-lg px-2 text-[0.8125rem] text-muted-foreground transition-colors hover:bg-surface-2 hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring aria-expanded:bg-surface-2 pointer-coarse:h-11"
        aria-label={`Modo de respuesta: ${current?.label ?? ""}`}>
        <span className="max-w-[8rem] truncate">{current?.label}</span>
        <ChevronDownIcon className="size-3.5" aria-hidden />
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="start" sideOffset={8} className="w-64">
        <DropdownMenuLabel>Modo de respuesta</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={value} onValueChange={(next) => onChange(String(next))}>
          {profiles.map((item) => <DropdownMenuRadioItem key={item.value} value={item.value}>{item.label}</DropdownMenuRadioItem>)}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
