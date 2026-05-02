import { supabaseAdmin } from "./lib/db/src/index.ts";

async function run() {
  const { data: authUsers } = await supabaseAdmin.auth.admin.listUsers();
  const users = authUsers?.users ?? [];

  for (const u of users) {
    console.log(`Checking: ${u.email}`);
    // Find in admin_users
    const { data: adminUser } = await supabaseAdmin
      .from('admin_users')
      .select('role')
      .eq('email', u.email)
      .maybeSingle();

    if (adminUser && adminUser.role.toLowerCase() === 'admin') {
      console.log(`Syncing admin role for ${u.email}`);
      await supabaseAdmin
        .from('user_roles')
        .upsert({ user_id: u.id, role: 'admin' }, { onConflict: 'user_id' });
    }
  }
}
run();
