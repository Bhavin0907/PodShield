import {
  Boxes,
  Container,
  GlobeLock,
  History,
  LayoutDashboard,
  Loader2,
  type LucideIcon,
  Menu,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  ScanSearch,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";

import { ScanProgressPanel } from "@/components/scan-progress";
import { ScannerStatusIndicator } from "@/components/scanner-status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useScan } from "@/lib/scan-context";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/images", label: "Images", icon: Boxes },
  { to: "/containers", label: "Containers", icon: Container },
  { to: "/registry", label: "Registry Scan", icon: GlobeLock },
  { to: "/history", label: "Scan History", icon: History },
  { to: "/rules", label: "Rules", icon: SlidersHorizontal },
  { to: "/settings", label: "Settings", icon: Settings },
];

const COLLAPSE_KEY = "podshield-sidebar-collapsed";

function Sidebar({ collapsed, mobileOpen, onNavigate }: { collapsed: boolean; mobileOpen: boolean; onNavigate: () => void }) {
  return (
    <aside
      className={cn(
        "fixed inset-y-0 left-0 z-40 flex flex-col border-r bg-card transition-all duration-200 lg:static lg:translate-x-0",
        collapsed ? "lg:w-[4.5rem]" : "lg:w-64",
        "w-64",
        mobileOpen ? "translate-x-0 shadow-2xl" : "-translate-x-full",
      )}
      aria-label="Primary"
    >
      <div className={cn("flex h-16 items-center gap-3 border-b px-5", collapsed && "lg:justify-center lg:px-0")}>
        <div className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-[0_0_20px_-4px_hsl(var(--primary)/0.6)]">
          <ShieldCheck className="size-5" />
        </div>
        <div className={cn("leading-tight", collapsed && "lg:hidden")}>
          <p className="text-base font-semibold tracking-tight">PodShield</p>
          <p className="text-[11px] text-muted-foreground">Image security auditor</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => {
          const link = (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  "group flex h-10 items-center gap-3 rounded-xl px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  collapsed && "lg:justify-center lg:px-0",
                  isActive
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                )
              }
            >
              <Icon className="size-[1.15rem] shrink-0" />
              <span className={cn(collapsed && "lg:hidden")}>{label}</span>
            </NavLink>
          );
          return collapsed ? (
            <Tooltip key={to}>
              <TooltipTrigger asChild>{link}</TooltipTrigger>
              <TooltipContent side="right" className="hidden lg:block">
                {label}
              </TooltipContent>
            </Tooltip>
          ) : (
            link
          );
        })}
      </nav>
      <div className={cn("border-t p-4 text-[11px] text-muted-foreground", collapsed && "lg:hidden")}>
        Runs locally. Scan data never leaves this host.
      </div>
    </aside>
  );
}

function TopBar({
  collapsed,
  onToggleCollapse,
  onOpenMobile,
}: {
  collapsed: boolean;
  onToggleCollapse: () => void;
  onOpenMobile: () => void;
}) {
  const navigate = useNavigate();
  const { theme, toggle } = useTheme();
  const { busy, start } = useScan();
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const typing = el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);
      if (e.key === "/" && !typing && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const onSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = query.trim();
    navigate(q ? `/images?q=${encodeURIComponent(q)}` : "/images");
  };

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur-md sm:px-6">
      <Button variant="ghost" size="icon" className="lg:hidden" onClick={onOpenMobile} aria-label="Open navigation">
        <Menu />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        className="hidden lg:inline-flex"
        onClick={onToggleCollapse}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
      </Button>

      <form onSubmit={onSearch} role="search" className="relative max-w-md flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search images by name or ID"
          aria-label="Search images"
          className="h-10 bg-muted/40 pl-9 pr-9"
        />
        <kbd className="pointer-events-none absolute right-3 top-1/2 hidden -translate-y-1/2 rounded border bg-background px-1.5 font-mono text-[10px] text-muted-foreground sm:block">
          /
        </kbd>
      </form>

      <div className="ml-auto flex items-center gap-2">
        <ScannerStatusIndicator />
        <Button variant="ghost" size="icon" onClick={toggle} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}>
          {theme === "dark" ? <Sun /> : <Moon />}
        </Button>
        <Button
          onClick={() => void start({ all: true }, "All images")}
          disabled={busy}
          className="h-10"
          aria-label={busy ? "Scanning" : "Scan all images"}
        >
          {busy ? <Loader2 className="animate-spin" /> : <ScanSearch />}
          <span className="hidden sm:inline">{busy ? "Scanning..." : "Scan all"}</span>
        </Button>
      </div>
    </header>
  );
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    try {
      localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, [collapsed]);

  useEffect(() => setMobileOpen(false), [location.pathname]);

  return (
    <div className="flex min-h-screen">
      <Sidebar collapsed={collapsed} mobileOpen={mobileOpen} onNavigate={() => setMobileOpen(false)} />
      {mobileOpen && (
        <div className="fixed inset-0 z-30 bg-black/50 backdrop-blur-sm lg:hidden" onClick={() => setMobileOpen(false)} aria-hidden />
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar collapsed={collapsed} onToggleCollapse={() => setCollapsed((c) => !c)} onOpenMobile={() => setMobileOpen(true)} />
        <main className="mx-auto w-full max-w-[1400px] flex-1 animate-fade-in p-4 sm:p-6 lg:p-8" key={location.pathname}>
          <Outlet />
        </main>
      </div>
      <ScanProgressPanel />
    </div>
  );
}
