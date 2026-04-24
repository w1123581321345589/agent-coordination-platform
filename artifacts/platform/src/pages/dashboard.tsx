import React from "react";
import { useGetDashboardSummary } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Activity, ShieldAlert, Cpu, GitMerge } from "lucide-react";

export default function Dashboard() {
  const { data: summary, isLoading } = useGetDashboardSummary();

  if (isLoading || !summary) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-mono font-bold tracking-tight">System Status</h1>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i} className="bg-card">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-4 rounded-full" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-mono font-bold tracking-tight">System Status</h1>
        <p className="text-muted-foreground">Live operations overview and telemetry.</p>
      </div>
      
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-card border-l-4 border-l-primary">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Active Agents</CardTitle>
            <Cpu className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{summary.activeAgents} <span className="text-sm font-normal text-muted-foreground">/ {summary.totalAgents}</span></div>
          </CardContent>
        </Card>

        <Card className="bg-card border-l-4 border-l-blue-500">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Active Sessions</CardTitle>
            <Activity className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{summary.activeSessions}</div>
            <p className="text-xs text-muted-foreground mt-1">{summary.messagesRouted} messages routed</p>
          </CardContent>
        </Card>

        <Card className="bg-card border-l-4 border-l-destructive">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Threats (24h)</CardTitle>
            <ShieldAlert className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-destructive">{summary.threatsFired24h}</div>
            <p className="text-xs text-muted-foreground mt-1">{summary.threatsDetected} total detected</p>
          </CardContent>
        </Card>

        <Card className="bg-card border-l-4 border-l-amber-500">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Pending Work</CardTitle>
            <GitMerge className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-amber-500">{summary.pendingWorkItems}</div>
            <p className="text-xs text-muted-foreground mt-1">In recovery queue</p>
          </CardContent>
        </Card>
      </div>

      {/* Placeholder for more dense data blocks */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card className="bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-mono">Meta-Learner Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center border-b border-border pb-2">
                <span className="text-muted-foreground text-sm">Active Strategies</span>
                <span className="font-mono font-bold">{summary.activeStrategies}</span>
              </div>
              <div className="flex justify-between items-center border-b border-border pb-2">
                <span className="text-muted-foreground text-sm">Pending Proposals</span>
                <span className="font-mono font-bold">{summary.pendingProposals}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-muted-foreground text-sm">Tournaments Run</span>
                <span className="font-mono font-bold">{summary.tournamentsRun}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
