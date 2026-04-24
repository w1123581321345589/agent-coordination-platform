import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  useListStrategies, 
  useCreateStrategy, 
  useProposeStrategySwitch, 
  useApproveStrategy, 
  useRejectStrategy, 
  useRollbackStrategy, 
  useLintStrategy, 
  useGetLearningCurve,
  getListStrategiesQueryKey,
  getLintStrategyQueryKey
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { Shield, Plus, Bug, Check, X, RotateCcw, ArrowRight } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";

const createSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  domain: z.string().min(1),
  coordinationPattern: z.enum(["hierarchical", "debate", "parallel", "hybrid"])
});

export default function Strategies() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);
  const [lintingId, setLintingId] = useState<number | null>(null);

  const { data: strategies, isLoading: stratLoading } = useListStrategies();
  const { data: curveData, isLoading: curveLoading } = useGetLearningCurve();
  const { data: lintResult, isFetching: lintLoading } = useLintStrategy(lintingId || 0, {
    query: { enabled: !!lintingId, queryKey: getLintStrategyQueryKey(lintingId || 0) }
  });

  const create = useCreateStrategy();
  const propose = useProposeStrategySwitch();
  const approve = useApproveStrategy();
  const reject = useRejectStrategy();
  const rollback = useRollbackStrategy();

  const form = useForm<z.infer<typeof createSchema>>({
    resolver: zodResolver(createSchema),
    defaultValues: { name: "", description: "", domain: "", coordinationPattern: "hierarchical" }
  });

  const onSubmit = (values: z.infer<typeof createSchema>) => {
    create.mutate({ data: values }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListStrategiesQueryKey() });
        setIsOpen(false);
        form.reset();
        toast({ title: "Strategy created" });
      }
    });
  };

  const handleAction = (id: number, action: string) => {
    const mutator = 
      action === "propose" ? propose : 
      action === "approve" ? approve : 
      action === "reject" ? reject : rollback;

    mutator.mutate({ id }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListStrategiesQueryKey() });
        toast({ title: `Strategy ${action}d` });
      }
    });
  };

  const getStageColor = (stage: string) => {
    switch (stage) {
      case "ingest": return "bg-slate-500/10 text-slate-500 border-slate-500/20";
      case "propose": return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      case "lint": return "bg-purple-500/10 text-purple-500 border-purple-500/20";
      case "active": return "bg-green-500/10 text-green-500 border-green-500/20";
      case "rejected": return "bg-red-500/10 text-red-500 border-red-500/20";
      case "rolled_back": return "bg-amber-500/10 text-amber-500 border-amber-500/20";
      case "expired": return "bg-gray-500/10 text-gray-500 border-gray-500/20";
      default: return "";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-mono font-bold tracking-tight">Meta-Learner</h1>
          <p className="text-muted-foreground">Manage and evolve agent coordination strategies over time.</p>
        </div>
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
          <DialogTrigger asChild>
            <Button><Plus className="mr-2 h-4 w-4" />Create Strategy</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>New Meta-Strategy</DialogTitle></DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField control={form.control} name="name" render={({field}) => (
                  <FormItem><FormLabel>Name</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="description" render={({field}) => (
                  <FormItem><FormLabel>Description</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="domain" render={({field}) => (
                  <FormItem><FormLabel>Domain</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="coordinationPattern" render={({field}) => (
                  <FormItem>
                    <FormLabel>Pattern</FormLabel>
                    <Select onValueChange={field.onChange} defaultValue={field.value}>
                      <FormControl><SelectTrigger><SelectValue/></SelectTrigger></FormControl>
                      <SelectContent>
                        <SelectItem value="hierarchical">Hierarchical</SelectItem>
                        <SelectItem value="debate">Debate</SelectItem>
                        <SelectItem value="parallel">Parallel</SelectItem>
                        <SelectItem value="hybrid">Hybrid</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormItem>
                )} />
                <Button type="submit" className="w-full" disabled={create.isPending}>Create Strategy</Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <Card className="bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-mono">Strategy Learning Curve (Escalation Rate)</CardTitle>
        </CardHeader>
        <CardContent className="h-[300px]">
          {curveLoading ? <Skeleton className="h-full w-full" /> : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis dataKey="evidenceCount" type="category" allowDuplicatedCategory={false} tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: "hsl(var(--card))", borderColor: "hsl(var(--border))", borderRadius: "8px" }} />
                <Legend />
                {Array.from(new Set(curveData?.map(d => d.strategyId))).map((id, i) => {
                  const data = curveData?.filter(d => d.strategyId === id);
                  const color = `hsl(${i * 60 + 200}, 70%, 50%)`;
                  return (
                    <Line key={id} data={data} type="monotone" dataKey="escalationRate" stroke={color} strokeWidth={2} name={`Strategy ${id}`} dot={false} />
                  );
                })}
              </LineChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {stratLoading ? Array.from({length: 3}).map((_, i) => <Skeleton key={i} className="h-48 w-full" />) : strategies?.map(s => (
          <Card key={s.id} className="bg-card flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex justify-between items-start mb-2">
                <Badge variant="outline" className={getStageColor(s.lifecycleStage)}>{s.lifecycleStage.toUpperCase()}</Badge>
                <Badge variant="secondary" className="font-mono text-[10px]">{s.domain}</Badge>
              </div>
              <CardTitle className="text-lg">{s.name}</CardTitle>
            </CardHeader>
            <CardContent className="flex-1 space-y-3">
              <p className="text-sm text-muted-foreground line-clamp-2">{s.description}</p>
              <div><Badge variant="outline" className="font-mono text-[10px] bg-background">{s.coordinationPattern}</Badge></div>
              
              {lintingId === s.id && (
                <div className="mt-4 p-3 bg-muted/30 rounded-md border border-border">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-bold font-mono">Lint Results</span>
                    {lintLoading ? <Skeleton className="h-4 w-12" /> : (
                      <Badge className={lintResult?.passed ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500"}>
                        {lintResult?.passed ? "PASSED" : "FAILED"}
                      </Badge>
                    )}
                  </div>
                  <div className="space-y-2 max-h-32 overflow-y-auto pr-2">
                    {!lintLoading && lintResult?.issues.map((issue, i) => (
                      <div key={i} className="flex gap-2 text-xs">
                        {issue.severity === 'error' ? <X className="h-3 w-3 text-red-500 flex-shrink-0 mt-0.5"/> : <AlertCircle className="h-3 w-3 text-amber-500 flex-shrink-0 mt-0.5"/>}
                        <div>
                          <span className="font-mono font-medium">{issue.code}</span>: <span className="text-muted-foreground">{issue.message}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                  <Button size="sm" variant="ghost" className="w-full mt-2 h-6 text-[10px]" onClick={() => setLintingId(null)}>Close</Button>
                </div>
              )}
            </CardContent>
            <CardFooter className="pt-2 border-t border-border mt-auto flex flex-wrap gap-2">
              {s.lifecycleStage === "ingest" && (
                <Button size="sm" variant="default" className="flex-1 bg-blue-600 hover:bg-blue-700" onClick={() => handleAction(s.id, "propose")}>
                  <ArrowRight className="h-4 w-4 mr-1"/> Propose
                </Button>
              )}
              {s.lifecycleStage === "propose" && (
                <>
                  <Button size="sm" variant="default" className="flex-1 bg-green-600 hover:bg-green-700" onClick={() => handleAction(s.id, "approve")}>
                    <Check className="h-4 w-4 mr-1"/> Approve
                  </Button>
                  <Button size="sm" variant="destructive" className="flex-1" onClick={() => handleAction(s.id, "reject")}>
                    <X className="h-4 w-4 mr-1"/> Reject
                  </Button>
                </>
              )}
              {s.lifecycleStage === "active" && (
                <Button size="sm" variant="outline" className="flex-1 text-amber-500 border-amber-500/50 hover:bg-amber-500/10" onClick={() => handleAction(s.id, "rollback")}>
                  <RotateCcw className="h-4 w-4 mr-1"/> Rollback
                </Button>
              )}
              {lintingId !== s.id && (
                <Button size="sm" variant="secondary" className="w-full" onClick={() => setLintingId(s.id)}>
                  <Bug className="h-4 w-4 mr-1"/> Run Linter
                </Button>
              )}
            </CardFooter>
          </Card>
        ))}
      </div>
    </div>
  );
}

import { AlertCircle } from "lucide-react";
