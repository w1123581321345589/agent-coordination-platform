import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  useListAgents, 
  useRegisterAgent, 
  useUpdateAgent, 
  useDeleteAgent,
  getListAgentsQueryKey
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
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";
import { Cpu, MoreVertical, Trash2, Plus } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const registerSchema = z.object({
  name: z.string().min(1, "Name is required"),
  role: z.string().min(1, "Role is required"),
  provider: z.string().min(1, "Provider is required"),
  capabilities: z.string().min(1, "Capabilities are required"),
  status: z.enum(["active", "paused", "retired"]),
});

export default function Agents() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);

  const { data: agents, isLoading } = useListAgents();
  const registerAgent = useRegisterAgent();
  const updateAgent = useUpdateAgent();
  const deleteAgent = useDeleteAgent();

  const form = useForm<z.infer<typeof registerSchema>>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      name: "",
      role: "",
      provider: "",
      capabilities: "",
      status: "active",
    },
  });

  const onSubmit = (values: z.infer<typeof registerSchema>) => {
    registerAgent.mutate({
      data: {
        ...values,
        capabilities: values.capabilities.split(",").map(c => c.trim()).filter(Boolean),
      }
    }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListAgentsQueryKey() });
        setIsRegisterOpen(false);
        form.reset();
        toast({ title: "Agent registered successfully" });
      },
      onError: () => {
        toast({ title: "Failed to register agent", variant: "destructive" });
      }
    });
  };

  const handleStatusChange = (id: number, status: "active" | "paused" | "retired") => {
    updateAgent.mutate({ id, data: { status } }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListAgentsQueryKey() });
        toast({ title: "Status updated" });
      }
    });
  };

  const handleDelete = (id: number) => {
    deleteAgent.mutate({ id }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListAgentsQueryKey() });
        toast({ title: "Agent deleted" });
      }
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active": return "bg-green-500/10 text-green-500 border-green-500/20";
      case "paused": return "bg-amber-500/10 text-amber-500 border-amber-500/20";
      case "retired": return "bg-slate-500/10 text-slate-500 border-slate-500/20";
      default: return "";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-mono font-bold tracking-tight">Agent Registry</h1>
          <p className="text-muted-foreground">Manage and monitor all active agents.</p>
        </div>
        <Dialog open={isRegisterOpen} onOpenChange={setIsRegisterOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-register-agent">
              <Plus className="mr-2 h-4 w-4" />
              Register Agent
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Register New Agent</DialogTitle>
            </DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Name</FormLabel>
                      <FormControl><Input {...field} data-testid="input-name" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="role"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Role</FormLabel>
                      <FormControl><Input {...field} data-testid="input-role" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="provider"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Provider</FormLabel>
                      <FormControl><Input {...field} data-testid="input-provider" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="capabilities"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Capabilities (comma separated)</FormLabel>
                      <FormControl><Input {...field} placeholder="e.g. text-generation, code-analysis" data-testid="input-capabilities" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="status"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Status</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger data-testid="select-status">
                            <SelectValue placeholder="Select status" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="active">Active</SelectItem>
                          <SelectItem value="paused">Paused</SelectItem>
                          <SelectItem value="retired">Retired</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit" className="w-full" disabled={registerAgent.isPending} data-testid="button-submit-register">
                  {registerAgent.isPending ? "Registering..." : "Register Agent"}
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
              <TableHead>Agent</TableHead>
              <TableHead>Provider</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Capabilities</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="w-[50px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <TableRow key={i}>
                  <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                  <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-48" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                  <TableCell><Skeleton className="h-8 w-8 rounded-md" /></TableCell>
                </TableRow>
              ))
            ) : agents?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                  No agents registered yet.
                </TableCell>
              </TableRow>
            ) : (
              agents?.map((agent) => (
                <TableRow key={agent.id} data-testid={`row-agent-${agent.id}`}>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="font-mono font-medium flex items-center gap-2">
                        <Cpu className="h-3 w-3 text-primary" />
                        {agent.name}
                      </span>
                      <span className="text-xs text-muted-foreground">{agent.role}</span>
                    </div>
                  </TableCell>
                  <TableCell>{agent.provider}</TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-auto p-0 hover:bg-transparent" data-testid={`button-status-${agent.id}`}>
                          <Badge variant="outline" className={`cursor-pointer ${getStatusColor(agent.status)}`} data-testid={`badge-status-${agent.id}`}>
                            {agent.status}
                          </Badge>
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => handleStatusChange(agent.id, "active")}>Active</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleStatusChange(agent.id, "paused")}>Paused</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleStatusChange(agent.id, "retired")}>Retired</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {agent.capabilities.map((cap, i) => (
                        <Badge key={i} variant="secondary" className="text-xs font-normal" data-testid={`badge-cap-${agent.id}-${i}`}>
                          {cap}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {format(new Date(agent.createdAt), "MMM d, HH:mm")}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" data-testid={`button-actions-${agent.id}`}>
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem 
                          className="text-destructive focus:text-destructive" 
                          onClick={() => handleDelete(agent.id)}
                          data-testid={`menu-delete-${agent.id}`}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
