import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  useListProposals, 
  useCreateProposal, 
  useApproveProposal, 
  useRejectProposal, 
  useRollbackProposal,
  useListFailurePatterns,
  getListProposalsQueryKey
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { Lightbulb, Plus, Check, X, RotateCcw } from "lucide-react";

const createSchema = z.object({
  title: z.string().min(1),
  description: z.string().min(1),
  proposedRole: z.string().min(1),
  proposedCapabilities: z.string().min(1)
});

export default function Proposals() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);

  const { data: proposals, isLoading: propsLoading } = useListProposals();
  const { data: patterns, isLoading: patternsLoading } = useListFailurePatterns();

  const create = useCreateProposal();
  const approve = useApproveProposal();
  const reject = useRejectProposal();
  const rollback = useRollbackProposal();

  const form = useForm<z.infer<typeof createSchema>>({
    resolver: zodResolver(createSchema),
    defaultValues: { title: "", description: "", proposedRole: "", proposedCapabilities: "" }
  });

  const onSubmit = (values: z.infer<typeof createSchema>) => {
    create.mutate({
      data: {
        ...values,
        proposedCapabilities: values.proposedCapabilities.split(",").map(s => s.trim()).filter(Boolean)
      }
    }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListProposalsQueryKey() });
        setIsOpen(false);
        form.reset();
        toast({ title: "Proposal created" });
      }
    });
  };

  const handleAction = (id: number, action: "approve" | "reject" | "rollback") => {
    const mutator = action === "approve" ? approve : action === "reject" ? reject : rollback;
    mutator.mutate({ id }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListProposalsQueryKey() });
        toast({ title: `Proposal ${action}d` });
      }
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "pending": return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      case "approved": return "bg-green-500/10 text-green-500 border-green-500/20";
      case "rejected": return "bg-red-500/10 text-red-500 border-red-500/20";
      case "rolled_back": return "bg-amber-500/10 text-amber-500 border-amber-500/20";
      case "expired": return "bg-slate-500/10 text-slate-500 border-slate-500/20";
      default: return "";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-mono font-bold tracking-tight">Proposal Engine</h1>
          <p className="text-muted-foreground">Review and manage AI-generated system changes.</p>
        </div>
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
          <DialogTrigger asChild>
            <Button data-testid="btn-create-prop"><Plus className="mr-2 h-4 w-4" />Create Proposal</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>Create Proposal</DialogTitle></DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField control={form.control} name="title" render={({field}) => (
                  <FormItem><FormLabel>Title</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="description" render={({field}) => (
                  <FormItem><FormLabel>Description</FormLabel><FormControl><Textarea {...field} /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="proposedRole" render={({field}) => (
                  <FormItem><FormLabel>Proposed Role</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="proposedCapabilities" render={({field}) => (
                  <FormItem><FormLabel>Capabilities (comma-separated)</FormLabel><FormControl><Input {...field} /></FormControl></FormItem>
                )} />
                <Button type="submit" className="w-full" disabled={create.isPending}>Submit Proposal</Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {propsLoading ? (
          Array.from({length: 3}).map((_, i) => <Skeleton key={i} className="h-48 w-full" />)
        ) : proposals?.length === 0 ? (
          <div className="col-span-full text-center text-muted-foreground py-12">No proposals yet</div>
        ) : proposals?.map(p => (
          <Card key={p.id} className="bg-card flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex justify-between items-start mb-2">
                <Badge variant="outline" className={getStatusColor(p.status)}>{p.status}</Badge>
                <span className="text-xs text-muted-foreground font-mono">{new Date(p.expiresAt).toLocaleDateString()}</span>
              </div>
              <CardTitle className="text-lg leading-tight">{p.title}</CardTitle>
            </CardHeader>
            <CardContent className="flex-1 space-y-3">
              <p className="text-sm text-muted-foreground line-clamp-2">{p.description}</p>
              <div>
                <Badge variant="secondary" className="font-mono text-[10px]">{p.proposedRole}</Badge>
              </div>
              <div className="flex flex-wrap gap-1">
                {p.proposedCapabilities.map(c => (
                  <Badge key={c} variant="outline" className="text-[10px] bg-background">{c}</Badge>
                ))}
              </div>
            </CardContent>
            <CardFooter className="pt-2 border-t border-border mt-auto flex gap-2">
              {p.status === "pending" && (
                <>
                  <Button size="sm" variant="default" className="flex-1 bg-green-600 hover:bg-green-700" onClick={() => handleAction(p.id, "approve")}>
                    <Check className="h-4 w-4 mr-1"/> Approve
                  </Button>
                  <Button size="sm" variant="destructive" className="flex-1" onClick={() => handleAction(p.id, "reject")}>
                    <X className="h-4 w-4 mr-1"/> Reject
                  </Button>
                </>
              )}
              {p.status === "approved" && (
                <Button size="sm" variant="outline" className="w-full text-amber-500 border-amber-500/50 hover:bg-amber-500/10" onClick={() => handleAction(p.id, "rollback")}>
                  <RotateCcw className="h-4 w-4 mr-1"/> Rollback
                </Button>
              )}
            </CardFooter>
          </Card>
        ))}
      </div>

      <Card className="bg-card mt-8">
        <CardHeader>
          <CardTitle className="text-lg font-mono">Failure Patterns & Triggers</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Domain</TableHead>
                <TableHead>Task Type</TableHead>
                <TableHead>Failure Count</TableHead>
                <TableHead>Last Failed</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {patternsLoading ? (
                <TableRow><TableCell colSpan={5}><Skeleton className="h-8 w-full"/></TableCell></TableRow>
              ) : patterns?.length === 0 ? (
                <TableRow><TableCell colSpan={5} className="text-center">No failure patterns detected</TableCell></TableRow>
              ) : patterns?.map(pt => (
                <TableRow key={pt.id}>
                  <TableCell><Badge variant="outline">{pt.domain}</Badge></TableCell>
                  <TableCell className="font-mono text-sm">{pt.taskType}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="h-2 rounded-full bg-red-500" style={{ width: `${Math.min(pt.failureCount * 2, 50)}px` }} />
                      <span className="font-mono font-bold text-red-500">{pt.failureCount}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{new Date(pt.lastFailedAt).toLocaleString()}</TableCell>
                  <TableCell>
                    {pt.proposalGenerated ? (
                      <Badge variant="secondary" className="bg-blue-500/10 text-blue-500">Proposal Generated</Badge>
                    ) : (
                      <Badge variant="outline" className="text-muted-foreground">Monitoring</Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
