import { ChevronDownIcon, InfoIcon, SlidersHorizontalIcon } from "lucide-react"
import { useEffect, useRef, useState } from "react"

import {
  DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuGroup, DropdownMenuLabel, DropdownMenuRadioGroup,
  DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { cn } from "@/lib/utils"

import { useSession } from "../app/session-context"
import { postForm } from "../transport/http"

type Model = { id: number; name: string; detail: string }

/** Provider and model for the next requests (session selection on the server). */
export function ModelMenu() {
  const session = useSession()
  const models = session.boot.models
  const [automatic, setAutomatic] = useState(models.automatic)
  const [engineId, setEngineId] = useState(models.engine_id)
  const [modelId, setModelId] = useState(models.model_id)
  const [options, setOptions] = useState<Model[]>(models.models)
  const [pending, setPending] = useState(false)
  const latest = useRef({ automatic, engineId, modelId })
  latest.current = { automatic, engineId, modelId }

  useEffect(() => {
    session.modelSettings = () => ({
      autoRoute: latest.current.automatic,
      engineId: latest.current.engineId === null ? null : String(latest.current.engineId),
      modelId: latest.current.modelId === null ? null : String(latest.current.modelId),
    })
  }, [session])

  if (!models.engines.length) return null
  const current = options.find((model) => model.id === modelId)
  const label = automatic ? "Automático" : current?.name ?? "Modelo"

  const chooseEngine = async (value: string) => {
    const id = Number(value)
    if (!Number.isFinite(id) || pending) return
    setPending(true)
    try {
      const data = await postForm<{ success?: boolean; available_models?: { id: number; name: string; model_id: string; supports_vision: boolean }[] }>(
        session.boot.urls.select_engine, { engine_id: String(id) })
      if (!data?.success) throw new Error("unavailable")
      const next = (data.available_models ?? []).map((model) => ({ id: model.id, name: model.name, detail: model.model_id + (model.supports_vision ? " · imágenes" : "") }))
      setEngineId(id)
      setOptions(next)
      setModelId(next[0]?.id ?? null)
      setAutomatic(false)
      session.toast(`Proveedor: ${models.engines.find((engine) => engine.id === id)?.name ?? ""}`)
    } catch {
      session.toast("No se pudo cambiar la selección.", true)
    } finally {
      setPending(false)
    }
  }
  const chooseModel = async (value: string) => {
    const id = Number(value)
    if (!Number.isFinite(id) || pending) return
    setPending(true)
    try {
      const data = await postForm<{ success?: boolean }>(session.boot.urls.select_model, { model_id: String(id) })
      if (!data?.success) throw new Error("unavailable")
      setModelId(id)
      setAutomatic(false)
    } catch {
      session.toast("No se pudo cambiar la selección.", true)
    } finally {
      setPending(false)
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cn(
          "flex h-8 min-w-0 items-center gap-1 rounded-lg px-2 text-[0.8125rem] font-medium text-muted-foreground transition-colors",
          "hover:bg-surface-2 hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring aria-expanded:bg-surface-2 aria-expanded:text-foreground pointer-coarse:h-11 pointer-coarse:min-w-11 pointer-coarse:justify-center",
        )}
        aria-label={`Modelo: ${label}`}
      >
        <SlidersHorizontalIcon className="size-4 shrink-0 sm:hidden" aria-hidden />
        <span className="hidden max-w-[12rem] truncate sm:inline">{label}</span>
        <ChevronDownIcon className="hidden size-3.5 shrink-0 sm:block" aria-hidden />
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="end" sideOffset={8} className="w-72 max-h-[min(30rem,var(--available-height))]">
        {models.automatic && (
          <>
            <DropdownMenuCheckboxItem checked={automatic} onCheckedChange={setAutomatic} closeOnClick={false} className="py-1.5">
              {models.difficulty ? "Selección automática según dificultad" : "Selección automática del modelo"}
            </DropdownMenuCheckboxItem>
            <DropdownMenuSeparator />
          </>
        )}
        <DropdownMenuGroup>
          <DropdownMenuLabel>Proveedor</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={engineId === null ? "" : String(engineId)} onValueChange={(value) => void chooseEngine(String(value))}>
            {models.engines.map((engine) => (
              <DropdownMenuRadioItem key={engine.id} value={String(engine.id)} closeOnClick={false} disabled={pending} className="items-start py-1.5">
                <span className="flex min-w-0 flex-col">
                  <span className="truncate">{engine.name}</span>
                  {engine.detail && <span className="truncate text-xs text-subtle-foreground">{engine.detail}</span>}
                </span>
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          <DropdownMenuLabel>Modelo</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={modelId === null ? "" : String(modelId)} onValueChange={(value) => void chooseModel(String(value))}>
            {options.map((model) => (
              <DropdownMenuRadioItem key={model.id} value={String(model.id)} disabled={pending} className="items-start py-1.5">
                <span className="flex min-w-0 flex-col">
                  <span className="truncate">{model.name}</span>
                  <span className="truncate text-xs text-subtle-foreground">{model.detail}</span>
                </span>
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
        {models.provider_limits && (
          <>
            <DropdownMenuSeparator />
            <p className="flex items-start gap-2 px-1.5 py-1.5 text-xs text-muted-foreground">
              <InfoIcon className="mt-px size-3.5 shrink-0" aria-hidden />
              El proveedor gestiona los límites de generación de esta cuenta.
            </p>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
