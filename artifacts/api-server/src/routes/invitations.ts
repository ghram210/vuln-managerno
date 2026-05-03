import { Router } from "express";
import { supabaseAdmin } from "@workspace/db";

const router = Router();

// Validate an invitation token (public - no auth needed)
router.get("/:token/validate", async (req, res) => {
  const { token } = req.params;
  try {
    const { data, error } = await supabaseAdmin.rpc("validate_invitation_token", {
      token_param: token,
    });
    if (error) throw error;
    res.json(data);
  } catch (err: any) {
    res.status(400).json({ valid: false, error: err.message });
  }
});

// Create an invitation link (admin only)
router.post("/", async (req, res): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    const token = authHeader.slice(7);

    // Verify the user and check admin role
    const { data: authData, error: authError } = await supabaseAdmin.auth.getUser(token);
    if (authError || !authData?.user) {
      res.status(401).json({ error: "Invalid token" });
      return;
    }
    const { user } = authData;

    const { data: roleData } = await supabaseAdmin
      .from("user_roles")
      .select("role")
      .eq("user_id", user.id)
      .maybeSingle();

    if (roleData?.role !== "admin") {
      res.status(403).json({ error: "Admin access required" });
      return;
    }

    const { email } = req.body as { email?: string };

    const { data, error } = await supabaseAdmin
      .from("invitation_links")
      .insert({
        created_by: user.id,
        email: email ?? null,
        max_uses: 1,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        is_active: true, // explicitly set it
      })
      .select("token, id, email, expires_at")
      .single();

    if (error) {
      console.error("Invitation insertion error:", error);
      let message = error.message;
      if (message.includes("is_active")) {
        message = "Database schema mismatch: missing 'is_active' column. Please run the provided SQL migration in Supabase.";
      }
      res.status(500).json({ error: message });
      return;
    }

    res.json({ token: data.token, id: data.id, email: data.email, expires_at: data.expires_at });
  } catch (err: any) {
    console.error("Invitation link creation crash:", err);
    res.status(500).json({ error: err.message || "Internal server error during invitation" });
  }
});

// Sync admin roles from admin_users to user_roles (admin bootstrap)
router.post("/sync-admin-roles", async (req, res): Promise<void> => {
  try {
    const { data: adminUsers } = await (supabaseAdmin
      .from("admin_users")
      .select("email, role") as any);

    if (!adminUsers) {
      res.json({ synced: 0 });
      return;
    }

    let synced = 0;
    const usersList: any[] = adminUsers;
    for (const au of usersList) {
      const email = au.email as string | undefined;
      const role = au.role as string | undefined;

      if (!email || role?.toLowerCase() !== "admin") continue;
      
      // Find auth user by email
      const { data: authListData } = await supabaseAdmin.auth.admin.listUsers();
      const authUsers: any[] = authListData?.users ?? [];
      const authUser = authUsers.find(
        (u: any) => (u.email ?? "").toLowerCase() === email.toLowerCase()
      );
      if (!authUser) continue;

      await supabaseAdmin
        .from("user_roles")
        .upsert({ user_id: authUser.id, role: "admin" }, { onConflict: "user_id" });
      synced++;
    }

    res.json({ synced });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// List invitations (admin only)
router.get("/", async (req, res): Promise<void> => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const token = authHeader.slice(7);

  const { data: authData, error: authError } = await supabaseAdmin.auth.getUser(token);
  if (authError || !authData?.user) {
    res.status(401).json({ error: "Invalid token" });
    return;
  }
  const { user } = authData;

  const { data: roleData } = await supabaseAdmin
    .from("user_roles")
    .select("role")
    .eq("user_id", user.id)
    .maybeSingle();

  if (roleData?.role !== "admin") {
    res.status(403).json({ error: "Admin access required" });
    return;
  }

  const { data, error } = await supabaseAdmin
    .from("invitation_links")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    res.status(500).json({ error: error.message });
    return;
  }
  res.json(data);
});

export default router;
