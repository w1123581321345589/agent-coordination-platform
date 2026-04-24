import React from "react";
import { 
  useListThreatRules, 
  useUpdateThreatRule, 
  useListThreatEvents, 
  useResolveThreatEvent, 
  useGetThreatStats,
  getListThreatRulesQueryKey,
  getListThreatEventsQueryKey,
  getGetThreatStatsQueryKey
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { ShieldAlert, Shield, AlertTriangle, AlertCircle, CheckCircle, ShieldCheck } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";

export default function Threats() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: stats, isLoading: statsLoading } = useGetThreatStats();
  const { data: rules, isLoading: rulesLoading } = useListThreatRules();
  const { data: events, isLoading: eventsLoading } = useListThreatEvents();

  const updateRule = useUpdateThreatRule();
  const resolveEvent = useResolveThreatEvent();

  const handleToggleRule = (id: number, isEnabled: boolean) => {
    updateRule.mutate({ id, data: { enabled: isEnabled } }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListThreatRulesQueryKey() });
        toast({ title: "Threat rule updated" });
      }
    });
  };

  const handleResolveEvent = (id: number) => {
    resolveEvent.mutate({ id }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListThreatEventsQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetThreatStatsQueryKey() });
        toast({ title: "Event resolved" });
      }
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-destructive border-destructive bg-destructive/10";
      case "high": return "text-orange-500 border-orange-500 bg-orange-500/10";
      case "medium": return "text-amber-500 border-amber-500 bg-amber-500/10";
      case "low": return "text-blue-500 border-blue-500 bg-blue-500/10";
      default: return "";
    }
  };

  const getSeverityHex = (severity: string) => {
    switch (severity) {
      case "critical": return "hsl(var(--destructive))";
      case "high": return "#f97316";
      case "medium": return "#f59e0b";
      case "low": return "#3b82f6";
      default: return "#888";
    }
  };

  const criticalCount = stats?.bySeverity.find(s => s.severity === "critical")?.count || 0;
  const highCount = stats?.bySeverity.find(s => s.severity === "high")?.count || 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-mono font-bold tracking-tight">Security Center</h1>
        <p className="text-muted-foreground">Monitor and manage threat events and rules.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Total Events</CardTitle>
            <ShieldAlert className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            {statsLoading ? <Skeleton className="h-8 w-16" /> : <div className="text-3xl font-bold font-mono">{stats?.totalEvents || 0}</div>}
          </CardContent>
        </Card>
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Unresolved</CardTitle>
            <AlertCircle className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            {statsLoading ? <Skeleton className="h-8 w-16" /> : <div className="text-3xl font-bold font-mono text-amber-500">{stats?.unresolvedEvents || 0}</div>}
          </CardContent>
        </Card>
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Critical Threats</CardTitle>
            <Shield className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            {statsLoading ? <Skeleton className="h-8 w-16" /> : <div className="text-3xl font-bold font-mono text-destructive">{criticalCount}</div>}
          </CardContent>
        </Card>
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">High Threats</CardTitle>
            <AlertTriangle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            {statsLoading ? <Skeleton className="h-8 w-16" /> : <div className="text-3xl font-bold font-mono text-orange-500">{highCount}</div>}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-card col-span-1">
          <CardHeader>
            <CardTitle className="text-lg font-mono">Threat Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {rulesLoading ? (
                Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)
              ) : rules?.length === 0 ? (
                <div className="text-sm text-muted-foreground">No threat rules configured.</div>
              ) : rules?.map((rule) => (
                <div key={rule.id} className="flex items-center justify-between border-b border-border pb-3 last:border-0 last:pb-0" data-testid={`rule-${rule.id}`}>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-medium">{rule.name}</span>
                      <Badge variant="outline" className={`text-[10px] uppercase h-5 px-1 ${getSeverityColor(rule.severity)}`}>{rule.severity}</Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="text-[10px] font-mono">{rule.ruleCode}</Badge>
                      <span className="text-xs text-muted-foreground">Fired: {rule.firedCount}</span>
                    </div>
                  </div>
                  <Switch 
                    checked={rule.enabled} 
                    onCheckedChange={(c) => handleToggleRule(rule.id, c)} 
                    data-testid={`switch-rule-${rule.id}`}
                  />
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card col-span-1">
          <CardHeader>
            <CardTitle className="text-lg font-mono">Events by Severity</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px]">
            {statsLoading || !stats ? (
              <div className="flex h-full items-center justify-center">
                <Skeleton className="h-full w-full" />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.bySeverity} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis dataKey="severity" tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: "hsl(var(--card))", borderColor: "hsl(var(--border))", borderRadius: "8px" }}
                    itemStyle={{ color: "hsl(var(--foreground))" }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {stats.bySeverity.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={getSeverityHex(entry.severity)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-mono">Threat Events Feed</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {eventsLoading ? (
              Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-24 w-full" />)
            ) : events?.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">No events recorded.</div>
            ) : events?.map((event) => (
              <div key={event.id} className={`flex flex-col sm:flex-row justify-between gap-4 p-4 border rounded-md border-l-4 ${getSeverityColor(event.severity)}`} data-testid={`event-${event.id}`}>
                <div className="space-y-2 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="outline" className={`uppercase ${getSeverityColor(event.severity)}`}>{event.severity}</Badge>
                    <span className="font-mono text-sm font-bold text-foreground">{event.ruleCode}</span>
                    <span className="text-xs text-muted-foreground ml-auto">{new Date(event.createdAt).toLocaleString()}</span>
                  </div>
                  <p className="text-sm text-foreground/80">{event.details}</p>
                  {event.agentId && (
                    <div className="text-xs text-muted-foreground font-mono mt-2">Agent ID: {event.agentId}</div>
                  )}
                </div>
                <div className="flex items-center justify-end">
                  {event.resolved ? (
                    <Badge variant="secondary" className="bg-green-500/10 text-green-500 hover:bg-green-500/20">
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Resolved
                    </Badge>
                  ) : (
                    <Button size="sm" onClick={() => handleResolveEvent(event.id)} data-testid={`btn-resolve-${event.id}`}>
                      Resolve
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
