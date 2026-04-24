import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  useListRoutingMappings, 
  useCreateRoutingMapping, 
  useUpdateRoutingMapping, 
  useDeleteRoutingMapping,
  useListRoutingPerformance,
  useRecordRoutingPerformance,
  getListRoutingMappingsQueryKey,
  getListRoutingPerformanceQueryKey
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { GitMerge, Plus, Trash2 } from "lucide-react";

const mappingSchema = z.object({
  role: z.string().min(1),
  provider: z.string().min(1),
  model: z.string().min(1),
  rationale: z.string().min(1)
});

const perfSchema = z.object({
  role: z.string().min(1),
  provider: z.string().min(1),
  model: z.string().min(1),
  taskType: z.string().min(1),
  qualityScore: z.number().min(0).max(1),
  costScore: z.number().min(0).max(1),
  latencyMs: z.number().min(0)
});

export default function Routing() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isMappingOpen, setIsMappingOpen] = useState(false);
  const [isPerfOpen, setIsPerfOpen] = useState(false);

  const { data: mappings, isLoading: mappingsLoading } = useListRoutingMappings();
  const { data: performances, isLoading: perfLoading } = useListRoutingPerformance();

  const createMapping = useCreateRoutingMapping();
  const updateMapping = useUpdateRoutingMapping();
  const deleteMapping = useDeleteRoutingMapping();
  const recordPerf = useRecordRoutingPerformance();

  const mappingForm = useForm<z.infer<typeof mappingSchema>>({
    resolver: zodResolver(mappingSchema),
    defaultValues: { role: "", provider: "", model: "", rationale: "" }
  });

  const perfForm = useForm<z.infer<typeof perfSchema>>({
    resolver: zodResolver(perfSchema),
    defaultValues: { role: "", provider: "", model: "", taskType: "", qualityScore: 0.8, costScore: 0.5, latencyMs: 500 }
  });

  const onMappingSubmit = (values: z.infer<typeof mappingSchema>) => {
    createMapping.mutate({ data: values }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListRoutingMappingsQueryKey() });
        setIsMappingOpen(false);
        mappingForm.reset();
        toast({ title: "Mapping added" });
      }
    });
  };

  const onPerfSubmit = (values: z.infer<typeof perfSchema>) => {
    recordPerf.mutate({ data: values }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListRoutingPerformanceQueryKey() });
        setIsPerfOpen(false);
        perfForm.reset();
        toast({ title: "Performance recorded" });
      }
    });
  };

  const toggleMapping = (id: number, isActive: boolean) => {
    updateMapping.mutate({ id, data: { active: isActive } }, {
      onSuccess: () => queryClient.invalidateQueries({ queryKey: getListRoutingMappingsQueryKey() })
    });
  };

  const removeMapping = (id: number) => {
    deleteMapping.mutate({ id }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListRoutingMappingsQueryKey() });
        toast({ title: "Mapping removed" });
      }
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-mono font-bold tracking-tight">Cross-Model Router</h1>
          <p className="text-muted-foreground">Manage dynamic routing rules and view performance data.</p>
        </div>
      </div>

      <Card className="bg-card">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-lg font-mono">Active Routing Mappings</CardTitle>
          <Dialog open={isMappingOpen} onOpenChange={setIsMappingOpen}>
            <DialogTrigger asChild>
              <Button size="sm" data-testid="btn-add-mapping"><Plus className="h-4 w-4 mr-2" />Add Mapping</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader><DialogTitle>Add Routing Mapping</DialogTitle></DialogHeader>
              <Form {...mappingForm}>
                <form onSubmit={mappingForm.handleSubmit(onMappingSubmit)} className="space-y-4">
                  <FormField control={mappingForm.control} name="role" render={({field}) => (
                    <FormItem><FormLabel>Role</FormLabel><FormControl><Input {...field} data-testid="in-role"/></FormControl></FormItem>
                  )} />
                  <FormField control={mappingForm.control} name="provider" render={({field}) => (
                    <FormItem><FormLabel>Provider</FormLabel><FormControl><Input {...field} data-testid="in-prov"/></FormControl></FormItem>
                  )} />
                  <FormField control={mappingForm.control} name="model" render={({field}) => (
                    <FormItem><FormLabel>Model</FormLabel><FormControl><Input {...field} data-testid="in-model"/></FormControl></FormItem>
                  )} />
                  <FormField control={mappingForm.control} name="rationale" render={({field}) => (
                    <FormItem><FormLabel>Rationale</FormLabel><FormControl><Input {...field} data-testid="in-rat"/></FormControl></FormItem>
                  )} />
                  <Button type="submit" className="w-full" disabled={createMapping.isPending}>Add Mapping</Button>
                </form>
              </Form>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          <div className="border rounded-md border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Role</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Model</TableHead>
                  <TableHead>Rationale</TableHead>
                  <TableHead>Active</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mappingsLoading ? (
                  <TableRow><TableCell colSpan={6}><Skeleton className="h-8 w-full" /></TableCell></TableRow>
                ) : mappings?.length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground">No mappings defined</TableCell></TableRow>
                ) : mappings?.map(m => (
                  <TableRow key={m.id} data-testid={`map-${m.id}`}>
                    <TableCell className="font-mono text-sm">{m.role}</TableCell>
                    <TableCell>{m.provider}</TableCell>
                    <TableCell><Badge variant="outline">{m.model}</Badge></TableCell>
                    <TableCell className="text-sm text-muted-foreground">{m.rationale}</TableCell>
                    <TableCell><Switch checked={m.active} onCheckedChange={c => toggleMapping(m.id, c)} /></TableCell>
                    <TableCell>
                      <Button variant="ghost" size="icon" onClick={() => removeMapping(m.id)}><Trash2 className="h-4 w-4 text-destructive" /></Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-lg font-mono">Performance Records</CardTitle>
          <Dialog open={isPerfOpen} onOpenChange={setIsPerfOpen}>
            <DialogTrigger asChild>
              <Button size="sm" variant="secondary" data-testid="btn-rec-perf"><Plus className="h-4 w-4 mr-2" />Record Performance</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader><DialogTitle>Record Performance</DialogTitle></DialogHeader>
              <Form {...perfForm}>
                <form onSubmit={perfForm.handleSubmit(onPerfSubmit)} className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <FormField control={perfForm.control} name="role" render={({field}) => (
                      <FormItem><FormLabel>Role</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                    )} />
                    <FormField control={perfForm.control} name="taskType" render={({field}) => (
                      <FormItem><FormLabel>Task Type</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                    )} />
                    <FormField control={perfForm.control} name="provider" render={({field}) => (
                      <FormItem><FormLabel>Provider</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                    )} />
                    <FormField control={perfForm.control} name="model" render={({field}) => (
                      <FormItem><FormLabel>Model</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                    )} />
                  </div>
                  <FormField control={perfForm.control} name="qualityScore" render={({field}) => (
                    <FormItem>
                      <FormLabel>Quality (0-1): {field.value}</FormLabel>
                      <FormControl><Slider min={0} max={1} step={0.01} value={[field.value]} onValueChange={v => field.onChange(v[0])} /></FormControl>
                    </FormItem>
                  )} />
                  <FormField control={perfForm.control} name="costScore" render={({field}) => (
                    <FormItem>
                      <FormLabel>Cost (0-1): {field.value}</FormLabel>
                      <FormControl><Slider min={0} max={1} step={0.01} value={[field.value]} onValueChange={v => field.onChange(v[0])} /></FormControl>
                    </FormItem>
                  )} />
                  <FormField control={perfForm.control} name="latencyMs" render={({field}) => (
                    <FormItem>
                      <FormLabel>Latency (ms)</FormLabel>
                      <FormControl><Input type="number" {...field} onChange={e => field.onChange(Number(e.target.value))} /></FormControl>
                    </FormItem>
                  )} />
                  <Button type="submit" className="w-full" disabled={recordPerf.isPending}>Save Record</Button>
                </form>
              </Form>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          <div className="border rounded-md border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Route</TableHead>
                  <TableHead>Task</TableHead>
                  <TableHead>Latency</TableHead>
                  <TableHead>Scores</TableHead>
                  <TableHead className="w-[200px]">Composite Score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {perfLoading ? (
                  <TableRow><TableCell colSpan={5}><Skeleton className="h-8 w-full" /></TableCell></TableRow>
                ) : performances?.length === 0 ? (
                  <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground">No records</TableCell></TableRow>
                ) : performances?.map(p => (
                  <TableRow key={p.id} data-testid={`perf-${p.id}`}>
                    <TableCell>
                      <div className="font-mono text-xs font-medium">{p.role}</div>
                      <div className="text-[10px] text-muted-foreground">{p.provider}/{p.model}</div>
                    </TableCell>
                    <TableCell><Badge variant="secondary" className="text-[10px] font-mono">{p.taskType}</Badge></TableCell>
                    <TableCell className="font-mono text-sm">{p.latencyMs}ms</TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Badge variant="outline" className="text-[10px] border-blue-500/50 text-blue-500">Q:{p.qualityScore}</Badge>
                        <Badge variant="outline" className="text-[10px] border-green-500/50 text-green-500">C:{p.costScore}</Badge>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Progress value={Number(p.compositeScore) * 100} className="h-2" />
                        <span className="text-xs font-mono text-muted-foreground">{p.compositeScore}</span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
