import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  useListContextDomains, 
  useCreateContextDomain, 
  useListShapleyValues, 
  useComputeShapleyValue, 
  useGetDiversityStats,
  getListContextDomainsQueryKey,
  getListShapleyValuesQueryKey
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { Network, Plus, Users, Percent, Shield, Calculator } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";

const domainSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  disclosureTier: z.number().min(1).max(3),
  dependencies: z.string()
});

export default function Context() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);

  const { data: stats, isLoading: statsLoading } = useGetDiversityStats();
  const { data: domains, isLoading: domainsLoading } = useListContextDomains();
  const { data: shapley, isLoading: shapleyLoading } = useListShapleyValues();

  const createDomain = useCreateContextDomain();
  const computeShapley = useComputeShapleyValue();

  const form = useForm<z.infer<typeof domainSchema>>({
    resolver: zodResolver(domainSchema),
    defaultValues: { name: "", description: "", disclosureTier: 1, dependencies: "" }
  });

  const onSubmit = (values: z.infer<typeof domainSchema>) => {
    createDomain.mutate({
      data: {
        ...values,
        dependencies: values.dependencies.split(",").map(s => s.trim()).filter(Boolean)
      }
    }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListContextDomainsQueryKey() });
        setIsOpen(false);
        form.reset();
        toast({ title: "Domain created" });
      }
    });
  };

  const handleCompute = () => {
    computeShapley.mutate({}, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListShapleyValuesQueryKey() });
        toast({ title: "Shapley values recomputed" });
      }
    });
  };

  const getTierColor = (tier: number) => {
    switch (tier) {
      case 1: return "bg-green-500/10 text-green-500 border-green-500/20";
      case 2: return "bg-amber-500/10 text-amber-500 border-amber-500/20";
      case 3: return "bg-red-500/10 text-red-500 border-red-500/20";
      default: return "";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-mono font-bold tracking-tight">Context & Shapley</h1>
        <p className="text-muted-foreground">Manage context domains and measure agent contributions.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Total Agents</CardTitle>
            <Users className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            {statsLoading ? <Skeleton className="h-8 w-16" /> : <div className="text-3xl font-bold font-mono">{stats?.totalAgents || 0}</div>}
          </CardContent>
        </Card>
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Diversity Score</CardTitle>
            <Percent className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            {statsLoading ? <Skeleton className="h-8 w-16" /> : <div className="text-3xl font-bold font-mono text-blue-500">{stats?.diversityScore || 0}%</div>}
          </CardContent>
        </Card>
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Redundancy</CardTitle>
            <Network className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            {statsLoading ? <Skeleton className="h-8 w-16" /> : <div className="text-3xl font-bold font-mono text-amber-500">{stats?.redundancyScore || 0}%</div>}
          </CardContent>
        </Card>
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Collapsed</CardTitle>
            <Shield className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            {statsLoading ? <Skeleton className="h-8 w-16" /> : <div className="text-3xl font-bold font-mono text-destructive">{stats?.collapsedDomains || 0}</div>}
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-mono">Top Contributors (Shapley Value)</CardTitle>
        </CardHeader>
        <CardContent className="h-[250px]">
          {statsLoading || !stats ? (
            <Skeleton className="h-full w-full" />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.topContributors} layout="vertical" margin={{ top: 0, right: 30, left: 40, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" horizontal={true} vertical={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="agentName" type="category" tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: "hsl(var(--card))", borderColor: "hsl(var(--border))", borderRadius: "8px" }} />
                <Bar dataKey="avgShapley" radius={[0, 4, 4, 0]} barSize={20} fill="hsl(var(--primary))" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      <div className="grid md:grid-cols-2 gap-6">
        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-lg font-mono">Context Domains</CardTitle>
            <Dialog open={isOpen} onOpenChange={setIsOpen}>
              <DialogTrigger asChild>
                <Button size="sm"><Plus className="h-4 w-4 mr-2" />Add Domain</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader><DialogTitle>Add Context Domain</DialogTitle></DialogHeader>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                    <FormField control={form.control} name="name" render={({field}) => (
                      <FormItem><FormLabel>Name</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                    )} />
                    <FormField control={form.control} name="description" render={({field}) => (
                      <FormItem><FormLabel>Description</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                    )} />
                    <FormField control={form.control} name="disclosureTier" render={({field}) => (
                      <FormItem>
                        <FormLabel>Disclosure Tier</FormLabel>
                        <Select onValueChange={v => field.onChange(parseInt(v, 10))} value={field.value.toString()}>
                          <FormControl><SelectTrigger><SelectValue/></SelectTrigger></FormControl>
                          <SelectContent>
                            <SelectItem value="1">Tier 1 (Public)</SelectItem>
                            <SelectItem value="2">Tier 2 (Internal)</SelectItem>
                            <SelectItem value="3">Tier 3 (Secret)</SelectItem>
                          </SelectContent>
                        </Select>
                      </FormItem>
                    )} />
                    <FormField control={form.control} name="dependencies" render={({field}) => (
                      <FormItem><FormLabel>Dependencies (csv)</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                    )} />
                    <Button type="submit" className="w-full" disabled={createDomain.isPending}>Create</Button>
                  </form>
                </Form>
              </DialogContent>
            </Dialog>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {domainsLoading ? <Skeleton className="h-32" /> : domains?.map(d => (
                <div key={d.id} className="border-b border-border pb-4 last:border-0 last:pb-0">
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-mono font-medium">{d.name}</span>
                    <Badge variant="outline" className={getTierColor(d.disclosureTier)}>Tier {d.disclosureTier}</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mb-2">{d.description}</p>
                  <div className="flex flex-wrap gap-1">
                    {d.dependencies.map(dep => <Badge key={dep} variant="secondary" className="text-[10px]">{dep}</Badge>)}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-lg font-mono">Shapley Values</CardTitle>
            <Button size="sm" variant="outline" onClick={handleCompute} disabled={computeShapley.isPending}>
              <Calculator className="h-4 w-4 mr-2" />Recompute
            </Button>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {shapleyLoading ? <Skeleton className="h-32" /> : shapley?.map(s => (
                <div key={s.id} className="space-y-2">
                  <div className="flex justify-between items-center text-sm">
                    <span className="font-mono">A_{s.agentId} <span className="text-muted-foreground text-xs">({s.taskType})</span></span>
                    <span className="font-mono font-bold text-primary">{s.shapleyValue}</span>
                  </div>
                  <Progress value={Number(s.shapleyValue) * 100} className="h-2 bg-muted/50" />
                  <div className="flex justify-between text-[10px] text-muted-foreground uppercase">
                    <span>{s.domain}</span>
                    <span>{s.samplesCount} samples</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
