import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  useListSessions, 
  useCreateSession, 
  useListMessages, 
  useRouteMessage,
  getListSessionsQueryKey,
  getListMessagesQueryKey,
  useListAgents
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";
import { Workflow, Plus, ChevronDown, ChevronRight, Send } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

const createSessionSchema = z.object({
  initiatorAgentId: z.coerce.number().min(1, "Initiator is required"),
  targetAgentId: z.coerce.number().min(1, "Target is required"),
  taskDescription: z.string().min(1, "Task description is required"),
});

const sendMessageSchema = z.object({
  fromAgentId: z.coerce.number().min(1, "Sender is required"),
  toAgentId: z.coerce.number().min(1, "Receiver is required"),
  messageType: z.enum(["task", "delegation", "response", "claim", "error"]),
  content: z.string().min(1, "Content is required"),
});

export default function Sessions() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [expandedSessionId, setExpandedSessionId] = useState<number | null>(null);

  const { data: sessions, isLoading: sessionsLoading } = useListSessions();
  const { data: agents } = useListAgents();
  const createSession = useCreateSession();
  const routeMessage = useRouteMessage();

  const form = useForm<z.infer<typeof createSessionSchema>>({
    resolver: zodResolver(createSessionSchema),
    defaultValues: {
      taskDescription: "",
    },
  });

  const getAgentName = (id: number) => {
    return agents?.find(a => a.id === id)?.name || `Agent ${id}`;
  };

  const onSubmit = (values: z.infer<typeof createSessionSchema>) => {
    createSession.mutate({ data: values }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListSessionsQueryKey() });
        setIsCreateOpen(false);
        form.reset();
        toast({ title: "Session created successfully" });
      },
      onError: () => {
        toast({ title: "Failed to create session", variant: "destructive" });
      }
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-mono font-bold tracking-tight">A2A Sessions</h1>
          <p className="text-muted-foreground">Monitor agent-to-agent communication streams.</p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-create-session">
              <Plus className="mr-2 h-4 w-4" />
              New Session
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Session</DialogTitle>
            </DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="initiatorAgentId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Initiator Agent</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value?.toString()}>
                        <FormControl>
                          <SelectTrigger data-testid="select-initiator">
                            <SelectValue placeholder="Select initiator" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {agents?.map(agent => (
                            <SelectItem key={agent.id} value={agent.id.toString()}>{agent.name}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="targetAgentId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Target Agent</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value?.toString()}>
                        <FormControl>
                          <SelectTrigger data-testid="select-target">
                            <SelectValue placeholder="Select target" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {agents?.map(agent => (
                            <SelectItem key={agent.id} value={agent.id.toString()}>{agent.name}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="taskDescription"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Task Description</FormLabel>
                      <FormControl><Textarea {...field} data-testid="input-task-desc" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit" className="w-full" disabled={createSession.isPending} data-testid="button-submit-session">
                  {createSession.isPending ? "Creating..." : "Create Session"}
                </Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="rounded-md border border-border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[40px]"></TableHead>
              <TableHead>Session ID</TableHead>
              <TableHead>Direction</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Task</TableHead>
              <TableHead>Messages</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sessionsLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <TableRow key={i}>
                  <TableCell><Skeleton className="h-4 w-4" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-12" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                  <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-48" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-8" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                </TableRow>
              ))
            ) : sessions?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                  No sessions active.
                </TableCell>
              </TableRow>
            ) : (
              sessions?.map((session) => (
                <React.Fragment key={session.id}>
                  <TableRow className="cursor-pointer" onClick={() => setExpandedSessionId(expandedSessionId === session.id ? null : session.id)} data-testid={`row-session-${session.id}`}>
                    <TableCell>
                      {expandedSessionId === session.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{session.id}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2 text-sm">
                        <span className="font-medium text-primary">{getAgentName(session.initiatorAgentId)}</span>
                        <span className="text-muted-foreground">→</span>
                        <span className="font-medium text-blue-400">{getAgentName(session.targetAgentId)}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`
                        ${session.status === 'active' ? 'bg-green-500/10 text-green-500 border-green-500/20' : 
                          session.status === 'completed' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' : 
                          'bg-amber-500/10 text-amber-500 border-amber-500/20'}`} data-testid={`badge-status-${session.id}`}>
                        {session.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate text-sm" title={session.taskDescription}>
                      {session.taskDescription}
                    </TableCell>
                    <TableCell>{session.messageCount}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {format(new Date(session.createdAt), "MMM d, HH:mm")}
                    </TableCell>
                  </TableRow>
                  {expandedSessionId === session.id && (
                    <TableRow>
                      <TableCell colSpan={7} className="p-0 border-b-0 bg-muted/30">
                        <div className="p-4 border-b border-border">
                          <SessionMessages sessionId={session.id} agents={agents || []} />
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function SessionMessages({ sessionId, agents }: { sessionId: number, agents: any[] }) {
  const { data: messages, isLoading } = useListMessages({ sessionId });
  const routeMessage = useRouteMessage();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const form = useForm<z.infer<typeof sendMessageSchema>>({
    resolver: zodResolver(sendMessageSchema),
    defaultValues: {
      messageType: "task",
      content: "",
    },
  });

  const onSubmit = (values: z.infer<typeof sendMessageSchema>) => {
    routeMessage.mutate({ data: { sessionId, ...values } }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListMessagesQueryKey() });
        queryClient.invalidateQueries({ queryKey: getListSessionsQueryKey() });
        form.reset({ ...form.getValues(), content: "" });
      },
      onError: () => {
        toast({ title: "Failed to send message", variant: "destructive" });
      }
    });
  };

  const getAgentName = (id: number) => agents?.find(a => a.id === id)?.name || `Agent ${id}`;

  return (
    <div className="space-y-4">
      <div className="space-y-2 max-h-[300px] overflow-y-auto pr-2">
        {isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-3/4" />
          </div>
        ) : messages?.length === 0 ? (
          <p className="text-sm text-muted-foreground py-4 text-center">No messages in this session.</p>
        ) : (
          messages?.map(msg => (
            <div key={msg.id} className="flex flex-col gap-1 p-3 rounded-md bg-card border border-border text-sm">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-primary text-xs">{getAgentName(msg.fromAgentId)}</span>
                  <span className="text-muted-foreground text-xs">→</span>
                  <span className="font-semibold text-blue-400 text-xs">{getAgentName(msg.toAgentId)}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary" className="text-[10px] uppercase h-5">{msg.messageType}</Badge>
                  <span className="text-xs text-muted-foreground">{format(new Date(msg.createdAt), "HH:mm:ss")}</span>
                </div>
              </div>
              <p className="mt-1 font-mono text-xs whitespace-pre-wrap text-foreground/90">{msg.content}</p>
            </div>
          ))
        )}
      </div>
      
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="flex items-end gap-3 pt-2 border-t border-border">
          <div className="flex-1 grid grid-cols-3 gap-3">
            <FormField
              control={form.control}
              name="fromAgentId"
              render={({ field }) => (
                <FormItem>
                  <Select onValueChange={field.onChange} value={field.value?.toString()}>
                    <FormControl><SelectTrigger className="h-8 text-xs"><SelectValue placeholder="From..." /></SelectTrigger></FormControl>
                    <SelectContent>
                      {agents.map(a => <SelectItem key={a.id} value={a.id.toString()}>{a.name}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="toAgentId"
              render={({ field }) => (
                <FormItem>
                  <Select onValueChange={field.onChange} value={field.value?.toString()}>
                    <FormControl><SelectTrigger className="h-8 text-xs"><SelectValue placeholder="To..." /></SelectTrigger></FormControl>
                    <SelectContent>
                      {agents.map(a => <SelectItem key={a.id} value={a.id.toString()}>{a.name}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="messageType"
              render={({ field }) => (
                <FormItem>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl><SelectTrigger className="h-8 text-xs"><SelectValue placeholder="Type..." /></SelectTrigger></FormControl>
                    <SelectContent>
                      <SelectItem value="task">Task</SelectItem>
                      <SelectItem value="delegation">Delegation</SelectItem>
                      <SelectItem value="response">Response</SelectItem>
                      <SelectItem value="claim">Claim</SelectItem>
                      <SelectItem value="error">Error</SelectItem>
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <div className="col-span-3">
              <FormField
                control={form.control}
                name="content"
                render={({ field }) => (
                  <FormItem>
                    <FormControl><Textarea placeholder="Message content..." className="min-h-[40px] text-xs font-mono" {...field} /></FormControl>
                  </FormItem>
                )}
              />
            </div>
          </div>
          <Button type="submit" size="icon" disabled={routeMessage.isPending} className="h-10 w-10">
            <Send className="h-4 w-4" />
          </Button>
        </form>
      </Form>
    </div>
  );
}
