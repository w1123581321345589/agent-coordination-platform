import { Router, type IRouter } from "express";
import healthRouter from "./health";
import dashboardRouter from "./dashboard";
import agentsRouter from "./agents";
import sessionsRouter from "./sessions";
import threatsRouter from "./threats";
import recoveryRouter from "./recovery";
import routingRouter from "./routing";
import proposalsRouter from "./proposals";
import contextRouter from "./context";
import tournamentsRouter from "./tournaments";
import strategiesRouter from "./strategies";

const router: IRouter = Router();

router.use(healthRouter);
router.use(dashboardRouter);
router.use(agentsRouter);
router.use(sessionsRouter);
router.use(threatsRouter);
router.use(recoveryRouter);
router.use(routingRouter);
router.use(proposalsRouter);
router.use(contextRouter);
router.use(tournamentsRouter);
router.use(strategiesRouter);

export default router;
