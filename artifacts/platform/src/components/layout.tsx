import React, { useState, useEffect } from "react";
import { Link, useLocation } from "wouter";
import { 
  Activity, 
  ShieldAlert, 
  Cpu, 
  GitMerge, 
  RefreshCw, 
  Workflow, 
  Network, 
  Trophy, 
  Lightbulb, 
  Menu,
  Shield
} from "lucide-react";
import { Button } from "@/components/ui/button";

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const [location] = useLocation();
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  // Force dark mode
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  const navItems = [
    { href: "/", label: "Dashboard", icon: Activity },
    { href: "/agents", label: "Agent Registry", icon: Cpu },
    { href: "/sessions", label: "A2A Sessions", icon: Workflow },
    { href: "/threats", label: "Security", icon: ShieldAlert },
    { href: "/recovery", label: "Recovery Router", icon: RefreshCw },
    { href: "/routing", label: "Cross-Model Router", icon: GitMerge },
    { href: "/proposals", label: "Proposal Engine", icon: Lightbulb },
    { href: "/context", label: "Context & Shapley", icon: Network },
    { href: "/tournaments", label: "Coordination Tourney", icon: Trophy },
    { href: "/strategies", label: "Meta-Learner", icon: Shield },
  ];

  return (
    <div className="flex h-screen w-full bg-background overflow-hidden text-foreground selection:bg-primary/30">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 border-r border-border bg-card transition-transform duration-300 ease-in-out md:static md:translate-x-0 ${isMobileOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="flex h-16 items-center px-6 border-b border-border">
          <div className="flex items-center gap-2 font-mono font-bold tracking-tight text-primary">
            <Cpu className="h-5 w-5" />
            <span>AGENT_COORD</span>
          </div>
        </div>
        <nav className="space-y-1 p-4 overflow-y-auto h-[calc(100vh-4rem)]">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location === item.href || (item.href !== "/" && location.startsWith(item.href));
            return (
              <Link key={item.href} href={item.href} onClick={() => setIsMobileOpen(false)}>
                <div className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors cursor-pointer ${isActive ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"}`}>
                  <Icon className="h-4 w-4" />
                  {item.label}
                </div>
              </Link>
            );
          })}
        </nav>
      </aside>

      {/* Main Content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <header className="flex h-16 items-center gap-4 border-b border-border bg-card/50 px-6 backdrop-blur-sm">
          <Button variant="ghost" size="icon" className="md:hidden" onClick={() => setIsMobileOpen(!isMobileOpen)}>
            <Menu className="h-5 w-5" />
          </Button>
          <div className="flex-1" />
          <div className="flex items-center gap-4 text-sm font-mono">
            <span className="flex items-center gap-2 text-primary">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
              SYS_ONLINE
            </span>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6 md:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
