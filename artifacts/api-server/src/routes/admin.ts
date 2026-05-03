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

// Delete a user (admin only)
router.delete("/users/:id", async (req, res): Promise<void> => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const token = authHeader.slice(7);

  // Verify the requester is an admin
  const { data: authData, error: authError } = await supabaseAdmin.auth.getUser(token);
  if (authError || !authData?.user) {
    res.status(401).json({ error: "Invalid token" });
    return;
  }

  const { data: roleData } = await supabaseAdmin
    .from("user_roles")
    .select("role")
    .eq("user_id", authData.user.id)
    .maybeSingle();

  if (roleData?.role !== "admin") {
    res.status(403).json({ error: "Admin access required" });
    return;
  }

  const userIdToDelete = req.params.id;

  try {
    // 0. Safety Check: Never allow deleting an admin via this route
    const { data: targetRoleData } = await supabaseAdmin
      .from("user_roles")
      .select("role")
      .eq("user_id", userIdToDelete)
      .maybeSingle();

    if (targetRoleData?.role === "admin") {
      res.status(403).json({ error: "Cannot delete an administrator account" });
      return;
    }

    // 1. Delete from admin_users (public table)
    const { error: adminTableError } = await supabaseAdmin
      .from("admin_users")
      .delete()
      .eq("id", userIdToDelete);

    if (adminTableError) throw adminTableError;

    // 2. Delete from user_roles
    await supabaseAdmin
      .from("user_roles")
      .delete()
      .eq("user_id", userIdToDelete);

    // 3. Delete from Supabase Auth (the core)
    const { error: authDeleteError } = await supabaseAdmin.auth.admin.deleteUser(userIdToDelete);
    if (authDeleteError) {
      console.warn("Auth user deletion failed (user might not exist in Auth):", authDeleteError.message);
    }

    res.json({ success: true, message: "User deleted successfully" });
  } catch (err: any) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
