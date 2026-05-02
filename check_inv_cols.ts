import { supabaseAdmin } from "./lib/db/src/index.ts";

async function check() {
  const { data, error } = await supabaseAdmin.from('invitation_links').select('*').limit(1);
  if (error) {
    console.log("Error selecting:", error.message);
  } else if (data && data.length > 0) {
    console.log("Columns:", Object.keys(data[0]));
  } else {
    console.log("No data, checking schema via RPC...");
    const { data: cols } = await supabaseAdmin.rpc('get_table_columns', { table_name_param: 'invitation_links' });
    console.log("Cols:", cols);
  }
}
check();
