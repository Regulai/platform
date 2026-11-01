import {
  BellIcon, BookMarkedIcon, Building2Icon, BuildingIcon, ChartColumnIcon, ClipboardListIcon, CpuIcon, FileTextIcon,
  FlaskConicalIcon, FolderOpenIcon, HouseIcon, KeyRoundIcon, LogOutIcon, MessageSquareIcon, PanelLeftCloseIcon,
  SearchIcon, SettingsIcon, ShieldCheckIcon, SparklesIcon, SquarePenIcon, Trash2Icon, UserIcon, UsersIcon,
  type LucideIcon,
} from "lucide-react"
import { useMemo, useState } from "react"

import { Button } from "@/components/ui/button"
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuGroup, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

import { useChat, useSession } from "./session-context"

const NAV_ICONS: Record<string, LucideIcon> = {
  home: HouseIcon, chat: MessageSquareIcon, skills: BookMarkedIcon, dashboard: ChartColumnIcon, prompts: FileTextIcon,
  rulesgroups: FolderOpenIcon, rules: ShieldCheckIcon, community: UsersIcon, alerts: BellIcon, obfuscation: KeyRoundIcon,
  ai_connections: CpuIcon, company: Building2Icon, users: UsersIcon, departments: BuildingIcon, engines: CpuIcon,
  audit: ClipboardListIcon, admin: SettingsIcon, simulator: FlaskConicalIcon,
}

/** Conversations, then the person: account menu with the app's sections and alerts. */
export function Sidebar({ onHide, onNavigate }: { onHide?: () => void; onNavigate?: () => void }) {
  const session = useSession()
  const boot = session.boot
  const threads = useChat((state) => state.threads)
  const active = useChat((state) => state.conversationId)
  const [query, setQuery] = useState("")
  const filtered = useMemo(() => {
    const value = query.trim().toLocaleLowerCase("es")
    if (!value) return threads
    return threads
      .map((group) => ({ ...group, items: group.items.filter((item) => item.title.toLocaleLowerCase("es").includes(value)) }))
      .filter((group) => group.items.length)
  }, [threads, query])
  const href = (id: number) => boot.urls.conversation.replace("{id}", String(id))
  const remove = (id: number) => boot.urls.delete.replace("{id}", String(id))

  return (
    <nav className="flex h-full min-h-0 flex-col" aria-label="Conversaciones">
      <div className="flex h-14 shrink-0 items-center gap-2 px-3">
        <a href={boot.urls.home} className="flex min-w-0 items-center gap-2 rounded-md px-1.5 py-1 text-[0.9375rem] font-semibold tracking-tight text-foreground pointer-coarse:min-h-11">
          <img src={boot.urls.logo} alt="" className="size-6 shrink-0" />
          <span>regul<span className="text-brand">AI</span></span>
        </a>
        {onHide && (
          <Tooltip>
            <TooltipTrigger render={<Button variant="ghost" size="icon" className="ml-auto text-muted-foreground" aria-label="Ocultar conversaciones" onClick={onHide} />}>
              <PanelLeftCloseIcon />
            </TooltipTrigger>
            <TooltipContent side="right">Ocultar conversaciones</TooltipContent>
          </Tooltip>
        )}
      </div>

      <div className="flex shrink-0 flex-col gap-1 px-3 pb-2">
        <a
          href={boot.urls.chat}
          className="flex h-9 items-center gap-2 rounded-lg px-2.5 text-sm font-medium text-foreground transition-colors hover:bg-surface-3/70 focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:h-11"
          onClick={onNavigate}
        >
          <SquarePenIcon className="size-4 text-muted-foreground" aria-hidden />
          Nueva conversación
        </a>
        <label className="flex h-9 items-center gap-2 rounded-lg px-2.5 text-sm text-muted-foreground transition-colors focus-within:bg-background focus-within:ring-1 focus-within:ring-input hover:bg-surface-3/50 pointer-coarse:h-11">
          <SearchIcon className="size-4 shrink-0" aria-hidden />
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Buscar"
            aria-label="Buscar conversaciones"
            autoComplete="off"
            className="h-full min-w-0 flex-1 bg-transparent text-foreground outline-none placeholder:text-subtle-foreground [&::-webkit-search-cancel-button]:hidden"
          />
        </label>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-3 pb-3 [scrollbar-width:thin]">
        {filtered.map((group) => (
          <section key={group.label} className="mt-3 first:mt-1">
            <h2 className="px-2.5 pb-1 text-xs font-medium text-subtle-foreground">{group.label}</h2>
            <ul className="flex flex-col gap-px">
              {group.items.map((item) => {
                const current = item.id === active
                return (
                  <li key={item.id} className="group/thread relative">
                    <a
                      href={href(item.id)}
                      aria-current={current ? "page" : undefined}
                      onClick={onNavigate}
                      className={cn(
                        "flex min-h-9 items-center gap-2 rounded-lg py-1.5 pr-9 pl-2.5 text-sm text-foreground/85 transition-colors hover:bg-surface-3/70 hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:min-h-11 pointer-coarse:pr-12",
                        current && "bg-surface-3 font-medium text-foreground",
                      )}
                    >
                      {/* Every title starts at the same edge; the agent mark follows it. */}
                      <span className="truncate">{item.title}</span>
                      {item.mode === "agent" && <SparklesIcon className="size-3.5 shrink-0 text-subtle-foreground" aria-label="Agente" role="img" />}
                    </a>
                    <a
                      href={remove(item.id)}
                      aria-label={`Eliminar «${item.title}»`}
                      title="Eliminar"
                      className="absolute top-1/2 right-1 flex size-7 -translate-y-1/2 items-center justify-center rounded-md text-subtle-foreground opacity-0 transition-opacity group-hover/thread:opacity-100 hover:bg-surface-3 hover:text-danger focus-visible:opacity-100 focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:right-0 pointer-coarse:size-11 pointer-coarse:opacity-70"
                    >
                      <Trash2Icon className="size-3.5" aria-hidden />
                    </a>
                  </li>
                )
              })}
            </ul>
          </section>
        ))}
        {!threads.length && <p className="px-2.5 py-3 text-sm text-subtle-foreground">Tus conversaciones aparecerán aquí.</p>}
        {threads.length > 0 && !filtered.length && <p className="px-2.5 py-3 text-sm text-subtle-foreground">Sin resultados.</p>}
      </div>

      <div className="flex shrink-0 items-center gap-1 px-3 py-3">
        <AccountMenu />
        <AlertsMenu />
      </div>
    </nav>
  )
}

function AccountMenu() {
  const boot = useSession().boot
  const user = boot.user
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <button
            type="button"
            className="flex min-h-10 min-w-0 flex-1 items-center gap-2.5 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-surface-3/70 focus-visible:outline-2 focus-visible:outline-ring aria-expanded:bg-surface-3"
            aria-label={`Cuenta de ${user.name} y secciones de regulAI`}
          />
        }
      >
        <span className="flex size-7 shrink-0 items-center justify-center overflow-hidden rounded-full bg-foreground text-xs font-semibold text-background">
          {user.avatar_url ? <img src={user.avatar_url} alt="" className="size-full object-cover" /> : user.initial}
        </span>
        <span className="min-w-0 flex-1 leading-tight">
          <span className="block truncate text-sm font-medium text-foreground">{user.name}</span>
          <span className="block truncate text-xs text-subtle-foreground">{user.company ?? "Sin empresa"}</span>
        </span>
      </DropdownMenuTrigger>
      {/* All the room above the trigger: with touch-sized rows a fixed cap cut the last item on phones. */}
      <DropdownMenuContent side="top" align="start" sideOffset={8} className="w-64">
        {boot.navigation.map((group, index) => (
          <DropdownMenuGroup key={group.label}>
            {index > 0 && <DropdownMenuSeparator />}
            <DropdownMenuLabel>{group.label}</DropdownMenuLabel>
            {group.items.map((item) => {
              const Icon = NAV_ICONS[item.key] ?? HouseIcon
              return (
                <DropdownMenuItem key={item.key} render={<a href={item.href} aria-current={item.active ? "page" : undefined} />} className="min-h-8 pointer-coarse:min-h-11">
                  <Icon className="text-muted-foreground" aria-hidden />
                  {item.label}
                </DropdownMenuItem>
              )
            })}
          </DropdownMenuGroup>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem render={<a href={boot.urls.profile} />} className="min-h-8 pointer-coarse:min-h-11">
          <UserIcon className="text-muted-foreground" aria-hidden />
          Mi perfil
        </DropdownMenuItem>
        <DropdownMenuItem render={<a href={boot.urls.logout} />} className="min-h-8 pointer-coarse:min-h-11">
          <LogOutIcon className="text-muted-foreground" aria-hidden />
          Cerrar sesión
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

const SEVERITY: Record<string, string> = { critical: "bg-danger", high: "bg-warning", medium: "bg-brand", low: "bg-subtle-foreground" }

function AlertsMenu() {
  const alerts = useSession().boot.alerts
  if (!alerts) return null
  const label = alerts.count ? `Alertas pendientes: ${alerts.count}` : "Alertas pendientes"
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" size="icon" className="relative size-10 shrink-0 text-muted-foreground" aria-label={label} />}>
        <BellIcon />
        {alerts.count > 0 && (
          <span className="absolute top-1.5 right-1.5 flex min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[0.625rem] leading-4 font-semibold text-white tabular-nums">
            {alerts.count > 99 ? "99+" : alerts.count}
          </span>
        )}
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="end" sideOffset={8} className="w-80">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="flex items-baseline justify-between">
            <span className="text-sm font-semibold text-foreground">Alertas pendientes</span>
            <span className="tabular-nums">{alerts.count ? `${alerts.count} sin resolver` : "Ninguna sin resolver"}</span>
          </DropdownMenuLabel>
          {alerts.recent.map((alert) => (
            <DropdownMenuItem key={alert.id} render={<a href={alert.href} />} className="items-start py-2">
              <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", SEVERITY[alert.severity] ?? "bg-subtle-foreground")} aria-hidden />
              <span className="min-w-0">
                <span className="block truncate font-medium">{alert.title}</span>
                <span className="block truncate text-xs text-muted-foreground">{alert.description}</span>
              </span>
            </DropdownMenuItem>
          ))}
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem render={<a href={alerts.href} />}>
          <BellIcon className="text-muted-foreground" aria-hidden />
          Ver todas las alertas
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
