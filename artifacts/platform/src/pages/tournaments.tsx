import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  useListTournaments, 
  useCreateTournament, 
  useGetTournament, 
  useScoreTournamentVariant, 
  useListWinnerPatterns,
  getListTournamentsQueryKey,
  getGetTournamentQueryKey
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Slider } from "@/components/ui/slider";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { Trophy, Plus, ChevronDown, Check } from "lucide-react";

const createSchema = z.object({
  taskDescription: z.string().min(1),
  domain: z.string().min(1),
  taskType: z.string().min(1)
});

const scoreSchema = z.object({
  qualityScore: z.number().min(0).max(1),
  efficiencyScore: z.number().min(0).max(1),
  costScore: z.number().min(0).max(1)
});

export default function Tournaments() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [scoringVariant, setScoringVariant] = useState<number | null>(null);

  const { data: tournaments, isLoading: tournLoading } = useListTournaments();
  const { data: patterns, isLoading: patLoading } = useListWinnerPatterns();
  const { data: expandedData, isLoading: expandedLoading } = useGetTournament(expandedId || 0, {
    query: { enabled: !!expandedId, queryKey: getGetTournamentQueryKey(expandedId || 0) }
  });

  const create = useCreateTournament();
  const scoreVariant = useScoreTournamentVariant();

  const form = useForm<z.infer<typeof createSchema>>({
    resolver: zodResolver(createSchema),
    defaultValues: { taskDescription: "", domain: "", taskType: "" }
  });

  const scoreForm = useForm<z.infer<typeof scoreSchema>>({
    resolver: zodResolver(scoreSchema),
    defaultValues: { qualityScore: 0.5, efficiencyScore: 0.5, costScore: 0.5 }
  });

  const onSubmit = (values: z.infer<typeof createSchema>) => {
    create.mutate({ data: values }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListTournamentsQueryKey() });
        setIsOpen(false);
        form.reset();
        toast({ title: "Tournament created" });
      }
    });
  };

  const onScoreSubmit = (values: z.infer<typeof scoreSchema>) => {
    if (!scoringVariant) return;
    scoreVariant.mutate({ id: scoringVariant, data: values }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getGetTournamentQueryKey(expandedId || 0) });
        queryClient.invalidateQueries({ queryKey: getListTournamentsQueryKey() });
        setScoringVariant(null);
        scoreForm.reset();
        toast({ title: "Variant scored" });
      }
    });
  };

  const toggleExpand = (id: number) => {
    setExpandedId(prev => prev === id ? null : id);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-mono font-bold tracking-tight">Coordination Tournaments</h1>
          <p className="text-muted-foreground">Test multi-agent topologies and evaluate the best pattern.</p>
        </div>
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
          <DialogTrigger asChild>
            <Button data-testid="btn-create-tourn"><Plus className="mr-2 h-4 w-4" />Create Tournament</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>New Tournament</DialogTitle></DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField control={form.control} name="taskDescription" render={({field}) => (
                  <FormItem><FormLabel>Task Description</FormLabel><FormControl><Textarea {...field} /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="domain" render={({field}) => (
                  <FormItem><FormLabel>Domain</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="taskType" render={({field}) => (
                  <FormItem><FormLabel>Task Type</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                )} />
                <Button type="submit" className="w-full" disabled={create.isPending}>Start Tournament</Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          {tournLoading ? <Skeleton className="h-64" /> : tournaments?.map(t => (
            <Card key={t.id} className="bg-card">
              <CardHeader className="cursor-pointer hover:bg-accent/50 transition-colors pb-4" onClick={() => toggleExpand(t.id)}>
                <div className="flex justify-between items-start gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-[10px]">{t.domain}</Badge>
                      <span className="font-mono text-sm font-bold">{t.taskType}</span>
                      <Badge className={t.status === 'completed' ? "bg-green-500/10 text-green-500" : "bg-blue-500/10 text-blue-500"}>{t.status}</Badge>
                    </div>
                    <p className="text-sm font-medium">{t.taskDescription}</p>
                  </div>
                  {t.winnerPattern && (
                    <Badge variant="secondary" className="bg-amber-500/20 text-amber-500 border-amber-500/50 flex-shrink-0">
                      <Trophy className="h-3 w-3 mr-1" />{t.winnerPattern}
                    </Badge>
                  )}
                  <ChevronDown className={`h-5 w-5 text-muted-foreground transition-transform ${expandedId === t.id ? 'rotate-180' : ''}`} />
                </div>
              </CardHeader>
              
              {expandedId === t.id && (
                <CardContent className="pt-0 border-t border-border">
                  {expandedLoading ? <Skeleton className="h-32 mt-4" /> : (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                      {expandedData?.variants.map(v => {
                        const isWinner = t.winnerPattern === v.pattern;
                        return (
                          <Card key={v.id} className={`bg-background ${isWinner ? 'border-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.2)]' : ''}`}>
                            <CardHeader className="p-3 pb-0">
                              <CardTitle className="text-sm font-mono flex items-center justify-between">
                                {v.pattern}
                                {isWinner && <Trophy className="h-3 w-3 text-amber-500" />}
                              </CardTitle>
                            </CardHeader>
                            <CardContent className="p-3 pt-2">
                              {v.compositeScore !== null ? (
                                <div className="space-y-1">
                                  <div className="text-2xl font-mono font-bold">{v.compositeScore}</div>
                                  <div className="text-[10px] text-muted-foreground flex justify-between">
                                    <span>Q:{v.qualityScore}</span>
                                    <span>E:{v.efficiencyScore}</span>
                                    <span>C:{v.costScore}</span>
                                  </div>
                                </div>
                              ) : (
                                <div className="py-2 text-center text-xs text-muted-foreground">Pending Score</div>
                              )}
                            </CardContent>
                            <CardFooter className="p-3 pt-0">
                              {v.compositeScore === null && (
                                <Dialog open={scoringVariant === v.id} onOpenChange={(open) => {
                                  if (open) setScoringVariant(v.id);
                                  else setScoringVariant(null);
                                }}>
                                  <DialogTrigger asChild>
                                    <Button size="sm" variant="outline" className="w-full h-7 text-xs">Score Variant</Button>
                                  </DialogTrigger>
                                  <DialogContent>
                                    <DialogHeader><DialogTitle>Score {v.pattern}</DialogTitle></DialogHeader>
                                    <Form {...scoreForm}>
                                      <form onSubmit={scoreForm.handleSubmit(onScoreSubmit)} className="space-y-4">
                                        {['qualityScore', 'efficiencyScore', 'costScore'].map(field => (
                                          <FormField key={field} control={scoreForm.control} name={field as any} render={({field: f}) => (
                                            <FormItem>
                                              <FormLabel className="capitalize">{field.replace('Score','')} (0-1): {f.value}</FormLabel>
                                              <FormControl><Slider min={0} max={1} step={0.01} value={[f.value]} onValueChange={v => f.onChange(v[0])} /></FormControl>
                                            </FormItem>
                                          )} />
                                        ))}
                                        <Button type="submit" className="w-full">Submit Scores</Button>
                                      </form>
                                    </Form>
                                  </DialogContent>
                                </Dialog>
                              )}
                            </CardFooter>
                          </Card>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              )}
            </Card>
          ))}
        </div>

        <div className="lg:col-span-1">
          <Card className="bg-card sticky top-6">
            <CardHeader>
              <CardTitle className="text-lg font-mono">Winner Patterns</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {patLoading ? <Skeleton className="h-32" /> : patterns?.map((p, i) => (
                  <div key={i} className="flex flex-col gap-1 border-b border-border pb-3 last:border-0 last:pb-0">
                    <div className="flex justify-between items-center">
                      <Badge variant="outline" className="text-amber-500 border-amber-500/50 bg-amber-500/10">
                        {p.pattern}
                      </Badge>
                      <span className="font-mono text-sm font-bold">{p.winCount} wins</span>
                    </div>
                    <div className="flex justify-between items-center text-xs text-muted-foreground mt-1">
                      <span>{p.domain} • {p.taskType}</span>
                      <span>Avg: {p.avgComposite}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
