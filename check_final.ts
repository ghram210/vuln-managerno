import { supabaseAdmin } from "./lib/db/src/index.ts";

async function check() {
  const { data: roles } = await supabaseAdmin.from('user_roles').select('*');
  console.log("Current User Roles:", roles);

  const { data: admins } = await supabaseAdmin.from('admin_users').select('*').eq('role', 'Admin');
  console.log("Admin Table Entries:", admins);

  const { data: authUsers } = await supabaseAdmin.auth.admin.listUsers();
  const users = authUsers?.users ?? [];
  for (const u of users) {
    console.log("Auth User:", u.id, u.email);
  }
}
check();
