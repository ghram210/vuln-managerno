import { Router } from "express";
import { supabaseAdmin } from "@workspace/db";
import crypto from "crypto";

const router = Router();

// ── Admin config ──────────────────────────────────────────────────────────────
const ADMIN_EMAILS = [
  "jehanmoshle@gmail.com",
  "gharamrahal6@gmail.com",
];

// Hardcoded admin whitelist — admins can always scan these without adding them
const HARDCODED_ADMIN_WHITELIST = [
  "localhost",
  "127.0.0.1",
  "testfire.net",
  "demo.testfire.net",
  "testphp.vulnweb.com",
  "testasp.vulnweb.com",
  "vulnweb.com",
  "scanme.nmap.org",
  "zero.webappsecurity.com",
  "dvwa.co.uk",
  "hackazon.webscantest.com",
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractDomain(target: string): string {
  try {
    const url = target.startsWith("http") ? target : `http://${target}`;
    return new URL(url).hostname.replace(/^www\./i, "").toLowerCase();
  } catch {
    return target.replace(/^www\./i, "").split("/")[0].toLowerCase();
  }
}

async function resolveUser(authHeader: string | undefined) {
  if (!authHeader?.startsWith("Bearer ")) return null;
  const { data, error } = await supabaseAdmin.auth.getUser(authHeader.slice(7));
  if (error || !data?.user) return null;
  return data.user;
}

async function isAdmin(userId: string): Promise<boolean> {
  const { data } = await (supabaseAdmin as any)
    .from("user_roles")
    .select("role")
    .eq("user_id", userId)
    .maybeSingle();
  if (data?.role === "admin") return true;
  const { data: authData } = await supabaseAdmin.auth.admin.getUserById(userId);
  return ADMIN_EMAILS.includes(authData?.user?.email?.toLowerCase() ?? "");
}

/** Fetch the HTTP-01 challenge file from a REAL internet domain. */
async function fetchVerifyToken(domain: string): Promise<string | null> {
  const url = `http://${domain}/.well-known/verify.txt`;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return (await res.text()).trim();
  } catch {
    return null;
  }
}

// ── GET /api/domains ──────────────────────────────────────────────────────────
router.get("/", async (req, res): Promise<void> => {
  const user = await resolveUser(req.headers.authorization);
  if (!user) { res.status(401).json({ error: "Unauthorized" }); return; }

  const { data, error } = await (supabaseAdmin as any)
    .from("user_domains")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: true });

  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json({ domains: data ?? [] });
});

// ── POST /api/domains ─────────────────────────────────────────────────────────
// Admin  → domain added immediately as "verified" (no challenge needed)
// User   → domain added as "pending" with a challenge token
router.post("/", async (req, res): Promise<void> => {
  const user = await resolveUser(req.headers.authorization);
  if (!user) { res.status(401).json({ error: "Unauthorized" }); return; }

  const raw: string = (req.body?.domain ?? "").trim();
  if (!raw) { res.status(400).json({ error: "domain is required" }); return; }

  const domain = extractDomain(raw);
  const admin  = await isAdmin(user.id);

  // Max 30 for admins, 5 for regular users
  const limit = admin ? 30 : 5;
  const { count } = await (supabaseAdmin as any)
    .from("user_domains")
    .select("*", { count: "exact", head: true })
    .eq("user_id", user.id);

  if ((count ?? 0) >= limit) {
    res.status(400).json({ error: `Maximum ${limit} domains allowed per account` });
    return;
  }

  // Admin: skip verification, add immediately as verified
  // User:  add as pending with a random challenge token
  const insertPayload = admin
    ? { user_id: user.id, domain, status: "verified", token: null }
    : { user_id: user.id, domain, status: "pending", token: crypto.randomBytes(32).toString("hex") };

  const { data, error } = await (supabaseAdmin as any)
    .from("user_domains")
    .insert(insertPayload)
    .select()
    .single();

  if (error) {
    if (error.code === "23505") {
      res.status(400).json({ error: "This domain is already in your list" });
    } else {
      res.status(500).json({ error: error.message });
    }
    return;
  }

  res.json({ domain: data, adminBypass: admin });
});

// ── POST /api/domains/:id/verify  (HTTP-01 challenge — users only) ────────────
router.post("/:id/verify", async (req, res): Promise<void> => {
  const user = await resolveUser(req.headers.authorization);
  if (!user) { res.status(401).json({ error: "Unauthorized" }); return; }

  const admin = await isAdmin(user.id);
  if (admin) {
    // Admins don't need verification — their domains are already verified
    res.json({ verified: true, message: "Admin domains are auto-verified" });
    return;
  }

  const { data: row, error: fetchErr } = await (supabaseAdmin as any)
    .from("user_domains")
    .select("*")
    .eq("id", req.params.id)
    .eq("user_id", user.id)
    .maybeSingle();

  if (fetchErr || !row) { res.status(404).json({ error: "Domain not found" }); return; }

  if (row.status === "verified") {
    res.json({ verified: true, message: "Already verified" });
    return;
  }

  const found = await fetchVerifyToken(row.domain);

  if (found === null) {
    res.json({
      verified: false,
      message:
        `Could not reach http://${row.domain}/.well-known/verify.txt — ` +
        `make sure you have created the verification file on your web server and that ` +
        `the domain is publicly accessible on the internet.`,
    });
    return;
  }

  if (found !== row.token) {
    res.json({
      verified: false,
      message:
        "Token mismatch — the file content does not match the expected token. " +
        "Ensure the file contains only the token text with no extra spaces or line breaks.",
    });
    return;
  }

  await (supabaseAdmin as any)
    .from("user_domains")
    .update({ status: "verified" })
    .eq("id", row.id);

  res.json({ verified: true });
});

// ── DELETE /api/domains/:id ────────────────────────────────────────────────────
router.delete("/:id", async (req, res): Promise<void> => {
  const user = await resolveUser(req.headers.authorization);
  if (!user) { res.status(401).json({ error: "Unauthorized" }); return; }

  const admin = await isAdmin(user.id);
  const q = (supabaseAdmin as any).from("user_domains").delete().eq("id", req.params.id);
  if (!admin) q.eq("user_id", user.id);
  await q;

  res.json({ success: true });
});

// ── GET /api/domains/check?target=…  (scan authorization gate) ───────────────
router.get("/check", async (req, res): Promise<void> => {
  const user = await resolveUser(req.headers.authorization);
  if (!user) { res.status(401).json({ error: "Unauthorized" }); return; }

  const target = (req.query.target as string | undefined)?.trim();
  if (!target) { res.status(400).json({ error: "target is required" }); return; }

  const domain = extractDomain(target);
  const admin  = await isAdmin(user.id);

  if (admin) {
    // 1. Hardcoded whitelist (always allowed for admins)
    const hardcoded = HARDCODED_ADMIN_WHITELIST.some(
      (w) => domain === w || domain.endsWith(`.${w}`)
    );
    if (hardcoded) {
      res.json({ allowed: true, reason: "admin_hardcoded_whitelist", domain });
      return;
    }

    // 2. Admin's own DB domains (all stored as verified immediately upon addition)
    const { data: dbRow } = await (supabaseAdmin as any)
      .from("user_domains")
      .select("id")
      .eq("user_id", user.id)
      .eq("domain", domain)
      .eq("status", "verified")
      .maybeSingle();

    if (dbRow) {
      res.json({ allowed: true, reason: "admin_custom_domain", domain });
      return;
    }

    // Admin tried to scan something not in any whitelist
    res.status(403).json({
      allowed: false,
      domain,
      reason: "not_authorized",
      message: `⛔ "${domain}" is not in your whitelist. Add it via Settings → My Domains to scan it.`,
    });
    return;
  }

  // Regular user: must have a verified domain in DB
  const { data } = await (supabaseAdmin as any)
    .from("user_domains")
    .select("id")
    .eq("user_id", user.id)
    .eq("domain", domain)
    .eq("status", "verified")
    .maybeSingle();

  if (data) {
    res.json({ allowed: true, reason: "verified_domain", domain });
  } else {
    res.status(403).json({
      allowed: false,
      domain,
      reason: "not_authorized",
      message:
        `⛔ "${domain}" is not authorized for scanning. ` +
        `Add and verify it in Settings → My Domains first.`,
    });
  }
});

// ── GET /api/domains/admin/user/:userId ───────────────────────────────────────
router.get("/admin/user/:userId", async (req, res): Promise<void> => {
  const user = await resolveUser(req.headers.authorization);
  if (!user) { res.status(401).json({ error: "Unauthorized" }); return; }
  if (!(await isAdmin(user.id))) { res.status(403).json({ error: "Admin only" }); return; }

  const { data, error } = await (supabaseAdmin as any)
    .from("user_domains")
    .select("*")
    .eq("user_id", req.params.userId)
    .order("created_at", { ascending: true });

  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json({ domains: data ?? [] });
});

export default router;
export { HARDCODED_ADMIN_WHITELIST, extractDomain };
