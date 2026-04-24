import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Layout } from "@/components/layout";
import NotFound from "@/pages/not-found";

import Dashboard from "@/pages/dashboard";
import Agents from "@/pages/agents";
import Sessions from "@/pages/sessions";
import Threats from "@/pages/threats";
import Recovery from "@/pages/recovery";
import Routing from "@/pages/routing";
import Proposals from "@/pages/proposals";
import Context from "@/pages/context";
import Tournaments from "@/pages/tournaments";
import Strategies from "@/pages/strategies";

const queryClient = new QueryClient();

function Router() {
  return (
    <Layout>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/agents" component={Agents} />
        <Route path="/sessions" component={Sessions} />
        <Route path="/threats" component={Threats} />
        <Route path="/recovery" component={Recovery} />
        <Route path="/routing" component={Routing} />
        <Route path="/proposals" component={Proposals} />
        <Route path="/context" component={Context} />
        <Route path="/tournaments" component={Tournaments} />
        <Route path="/strategies" component={Strategies} />
        <Route component={NotFound} />
      </Switch>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL?.replace(/\/$/, "") || ""}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
