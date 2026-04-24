import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  useListWorkItems, 
  useEnqueueWorkItem, 
  useClaimWorkItem, 
  useCompleteWorkItem, 
  useListRecoveryEvents,
  useListAgents,
  getListWorkItemsQueryKey,
  getListRecoveryEventsQueryKey
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { useToast } from "@/hooks/use-toast";
import { GitMerge, Plus, Activity, AlertCircle, CheckCircle } from "lucide-react";

const enqueueSchema = z.object({
  taskDescription: z.string().min(1),
  domain: z.string().min(1),
  priority: z.number().min(1).max(10),
  originalAgentId: z.number().optional()
});

export default function Recovery() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isEnqueueOpen, setIsEnqueueOpen] = useState(false);
  const [claimingWorkId, setClaimingWorkId] = useState<number | null>(null);
  const [claimAgentId, setClaimAgentId] = useState<string>("");

  const { data: workItems, isLoading: itemsLoading } = useListWorkItems();
  const { data: events, isLoading: eventsLoading } = useListRecoveryEvents();
  const { data: agents } = useListAgents();

  const enqueueWorkItem = useEnqueueWorkItem();
  const claimWorkItem = useClaimWorkItem();
  const completeWorkItem = useCompleteWorkItem();

  const form = useForm<z.infer<typeof enqueueSchema>>({
    resolver: zodResolver(enqueueSchema),
    defaultValues: {
      taskDescription: "",
      domain: "",
      priority: 5,
    }
  });

  const onEnqueueSubmit = (values: z.infer<typeof enqueueSchema>) => {
    enqueueWorkItem.mutate({ data: values }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListWorkItemsQueryKey() });
        setIsEnqueueOpen(false);
        form.reset();
        toast({ title: "Work item enqueued" });
      }
    });
  };

  const handleClaim = (id: number) => {
    if (!claimAgentId) return;
    claimWorkItem.mutate({ id, data: { agentId: parseInt(claimAgentId, 10) } }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListWorkItemsQueryKey() });
        setClaimingWorkId(null);
        setClaimAgentId("");
        toast({ title: "Work item claimed" });
      }
    });
  };

  const handleComplete = (id: number) => {
    completeWorkItem.mutate({ id }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListWorkItemsQueryKey() });
        toast({ title: "Work item completed" });
      }
    });
  };

  const queued = workItems?.filter(w => w.status === "queued") || [];
  const claimed = workItems?.filter(w => w.status === "claimed") || [];
  const completed = workItems?.filter(w => w.status === "completed" || w.status === "failed") || [];

  return (
    <div className="space-y-6 flex flex-col h-full">
      <div className="flex items-center justify-between">
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-mono font-bold tracking-tight">Recovery Router</h1>
          <p className="text-muted-foreground">Manage failed work and re-routing queues.</p>
        </div>
        <Dialog open={isEnqueueOpen} onOpenChange={setIsEnqueueOpen}>
          <DialogTrigger asChild>
            <Button data-testid="btn-enqueue">
              <Plus className="mr-2 h-4 w-4" />
              Enqueue Work Item
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Enqueue Work Item</DialogTitle>
            </DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onEnqueueSubmit)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="taskDescription"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Task Description</FormLabel>
                      <FormControl><Input {...field} data-testid="input-task-desc" /></FormControl>
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="domain"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Domain</FormLabel>
                      <FormControl><Input {...field} data-testid="input-domain" /></FormControl>
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="priority"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Priority (1-10)</FormLabel>
                      <FormControl>
                        <Slider min={1} max={10} step={1} value={[field.value]} onValueChange={v => field.onChange(v[0])} data-testid="slider-priority" />
                      </FormControl>
                      <div className="text-xs text-muted-foreground text-right">{field.value}</div>
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="originalAgentId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Original Agent (Optional)</FormLabel>
                      <Select onValueChange={v => field.onChange(parseInt(v, 10))} value={field.value?.toString() || ""}>
                        <FormControl>
                          <SelectTrigger data-testid="select-original-agent">
                            <SelectValue placeholder="Select Agent" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {agents?.map(a => (
                            <SelectItem key={a.id} value={a.id.toString()}>{a.name}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </FormItem>
                  )}
                />
                <Button type="submit" className="w-full" disabled={enqueueWorkItem.isPending} data-testid="btn-submit-enqueue">Submit</Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 flex-1 min-h-[400px]">
        {/* Queued */}
        <div className="flex flex-col gap-4">
          <div className="font-mono font-medium flex justify-between items-center px-2 py-1 bg-amber-500/10 text-amber-500 rounded-md">
            <span>QUEUED</span>
            <Badge variant="outline" className="border-amber-500/50 text-amber-500">{queued.length}</Badge>
          </div>
          <div className="flex-1 space-y-3">
            {itemsLoading ? <Skeleton className="h-32" /> : queued.map(item => (
              <Card key={item.id} className="border-amber-500/20 bg-card" data-testid={`workitem-${item.id}`}>
                <CardContent className="p-4 space-y-3">
                  <div className="flex justify-between items-start gap-2">
                    <Badge variant="outline" className="font-mono text-[10px]">{item.domain}</Badge>
                    <span className="text-xs font-mono text-muted-foreground">P{item.priority}</span>
                  </div>
                  <p className="text-sm font-medium">{item.taskDescription}</p>
                  {claimingWorkId === item.id ? (
                    <div className="flex flex-col gap-2 pt-2">
                      <Select value={claimAgentId} onValueChange={setClaimAgentId}>
                        <SelectTrigger className="h-8 text-xs" data-testid="select-claim-agent">
                          <SelectValue placeholder="Select agent to claim" />
                        </SelectTrigger>
                        <SelectContent>
                          {agents?.map(a => <SelectItem key={a.id} value={a.id.toString()}>{a.name}</SelectItem>)}
                        </SelectContent>
                      </Select>
                      <div className="flex gap-2">
                        <Button size="sm" className="flex-1 h-8 text-xs" onClick={() => handleClaim(item.id)} data-testid="btn-confirm-claim">Confirm</Button>
                        <Button size="sm" variant="ghost" className="flex-1 h-8 text-xs" onClick={() => setClaimingWorkId(null)}>Cancel</Button>
                      </div>
                    </div>
                  ) : (
                    <Button size="sm" variant="secondary" className="w-full h-8 text-xs bg-amber-500/10 text-amber-500 hover:bg-amber-500/20" onClick={() => setClaimingWorkId(item.id)} data-testid={`btn-claim-${item.id}`}>
                      Claim Work
                    </Button>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Claimed */}
        <div className="flex flex-col gap-4">
          <div className="font-mono font-medium flex justify-between items-center px-2 py-1 bg-blue-500/10 text-blue-500 rounded-md">
            <span>CLAIMED</span>
            <Badge variant="outline" className="border-blue-500/50 text-blue-500">{claimed.length}</Badge>
          </div>
          <div className="flex-1 space-y-3">
            {itemsLoading ? <Skeleton className="h-32" /> : claimed.map(item => (
              <Card key={item.id} className="border-blue-500/20 bg-card" data-testid={`workitem-${item.id}`}>
                <CardContent className="p-4 space-y-3">
                  <div className="flex justify-between items-start gap-2">
                    <Badge variant="outline" className="font-mono text-[10px]">{item.domain}</Badge>
                    <span className="text-xs font-mono text-blue-500">Agent {item.claimedByAgentId}</span>
                  </div>
                  <p className="text-sm font-medium">{item.taskDescription}</p>
                  <Button size="sm" variant="secondary" className="w-full h-8 text-xs bg-blue-500/10 text-blue-500 hover:bg-blue-500/20" onClick={() => handleComplete(item.id)} data-testid={`btn-complete-${item.id}`}>
                    Mark Complete
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Completed / Failed */}
        <div className="flex flex-col gap-4">
          <div className="font-mono font-medium flex justify-between items-center px-2 py-1 bg-green-500/10 text-green-500 rounded-md">
            <span>COMPLETED/FAILED</span>
            <Badge variant="outline" className="border-green-500/50 text-green-500">{completed.length}</Badge>
          </div>
          <div className="flex-1 space-y-3">
            {itemsLoading ? <Skeleton className="h-32" /> : completed.map(item => (
              <Card key={item.id} className={`border-opacity-20 bg-card ${item.status === 'failed' ? 'border-red-500' : 'border-green-500'}`} data-testid={`workitem-${item.id}`}>
                <CardContent className="p-4 space-y-3">
                  <div className="flex justify-between items-start gap-2">
                    <Badge variant="outline" className={`font-mono text-[10px] ${item.status === 'failed' ? 'text-red-500 border-red-500/50' : 'text-green-500 border-green-500/50'}`}>
                      {item.status.toUpperCase()}
                    </Badge>
                    <span className="text-xs font-mono text-muted-foreground">P{item.priority}</span>
                  </div>
                  <p className="text-sm font-medium text-muted-foreground line-through">{item.taskDescription}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>

      <Card className="bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-mono">Recovery Events Bus</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {eventsLoading ? (
              <Skeleton className="h-24 w-full" />
            ) : events?.length === 0 ? (
              <div className="text-sm text-muted-foreground">No events recorded.</div>
            ) : events?.map((evt) => (
              <div key={evt.id} className="flex items-center gap-4 text-sm border-b border-border pb-3 last:border-0 last:pb-0" data-testid={`rec-event-${evt.id}`}>
                <div className="flex-shrink-0">
                  {evt.eventType === 'threat_fired' && <AlertCircle className="h-4 w-4 text-amber-500" />}
                  {(evt.eventType === 'agent_paused' || evt.eventType === 'work_returned') && <Activity className="h-4 w-4 text-blue-500" />}
                  {(evt.eventType === 'agent_claimed' || evt.eventType === 'work_completed') && <CheckCircle className="h-4 w-4 text-green-500" />}
                </div>
                <div className="flex-1 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <span className="font-mono text-foreground font-medium">A_{evt.agentId || 'SYS'}</span>
                  <span className="text-muted-foreground flex-1 truncate max-w-md" title={JSON.stringify(evt.payload)}>
                    {JSON.stringify(evt.payload).substring(0, 80)}...
                  </span>
                  <span className="text-xs text-muted-foreground">{new Date(evt.createdAt).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
