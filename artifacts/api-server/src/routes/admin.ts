import { Router } from "express";
import { supabaseAdmin } from "@workspace/db";

const router = Router();

// Sync admin roles - called once on setup to fix admin users
router.post("/sync-roles", async (req, res): Promise<void> => {
  try {
    const { data: adminUsers } = await (supabaseAdmin
      .from("admin_users")
      .select("email, role") as any);

    if (!adminUsers) {
      res.json({ synced: 0 });
      return;
    }

    const { data: authListData } = await supabaseAdmin.auth.admin.listUsers();
    const authUsers: any[] = authListData?.users ?? [];

    let synced = 0;
    const usersList: any[] = adminUsers;
    for (const au of usersList) {
      const email = au.email as string | undefined;
      const role = au.role as string | undefined;
      
      if (!email || role?.toLowerCase() !== "admin") continue;
      
      const authUser = authUsers.find(
        (u: any) => u.email?.toLowerCase() === email.toLowerCase()
      );
      if (!authUser) continue;

      await supabaseAdmin
        .from("user_roles")
        .upsert({ user_id: authUser.id, role: "admin" }, { onConflict: "user_id" });
      synced++;
    }

    res.json({ synced, message: `Synced ${synced} admin(s)` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
