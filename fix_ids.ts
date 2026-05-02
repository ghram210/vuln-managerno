import { supabaseAdmin } from "./lib/db/src/index.ts";

async function fix() {
  const { data: authUsers } = await supabaseAdmin.auth.admin.listUsers();
  const users = authUsers?.users ?? [];

  for (const u of users) {
    console.log(`Checking user: ${u.email} (${u.id})`);

    // Find if there's an admin_user with this email but different ID
    const { data: mismatch } = await supabaseAdmin
      .from('admin_users')
      .select('*')
      .eq('email', u.email)
      .neq('id', u.id);

    if (mismatch && mismatch.length > 0) {
      console.log(`Found mismatch for ${u.email}. Correcting...`);
      for (const m of mismatch) {
        // Delete the mismatching record
        await supabaseAdmin.from('admin_users').delete().eq('id', m.id);

        // Re-insert with correct ID and original data
        await supabaseAdmin.from('admin_users').insert({
          id: u.id,
          email: u.email,
          name: m.name,
          role: m.role,
          joined_at: m.joined_at
        });
      }
    }
  }
  console.log("ID correction complete.");
}
fix();
