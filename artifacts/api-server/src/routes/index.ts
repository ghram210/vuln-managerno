import { Router, type IRouter } from "express";
import healthRouter from "./health";
import invitationsRouter from "./invitations";
import adminRouter from "./admin";
import domainsRouter from "./domains";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/invitations", invitationsRouter);
router.use("/admin", adminRouter);
router.use("/domains", domainsRouter);

export default router;
