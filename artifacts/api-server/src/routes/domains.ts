import { Router } from "express";
import { supabaseAdmin } from "@workspace/db";
import { userDomainsTable } from "@workspace/db/schema";
import { eq, and, count } from "drizzle-orm";
import { db } from "@workspace/db";
import crypto from "crypto";
import httpx from "httpx"; // This is likely not available in node. using fetch instead.

const router = Router();

// Middleware to verify authentication
const authenticate = async (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const token = authHeader.slice(7);
  const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !user) {
    return res.status(401).json({ error: "Invalid token" });
  }
  req.user = user;
  next();
};

// GET /api/domains - List current user's domains
router.get("/", authenticate, async (req: any, res) => {
  try {
    const domains = await db
      .select()
      .from(userDomainsTable)
      .where(eq(userDomainsTable.userId, req.user.id));
    res.json(domains);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/domains - Add a domain
router.post("/", authenticate, async (req: any, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: "Domain is required" });

  try {
    // Check limit
    const [existingCount] = await db
      .select({ val: count() })
      .from(userDomainsTable)
      .where(eq(userDomainsTable.userId, req.user.id));

    if (existingCount.val >= 5) {
      return res.status(400).json({ error: "Maximum of 5 domains allowed" });
    }

    const verificationToken = crypto.randomBytes(16).toString("hex");
    const [newDomain] = await db
      .insert(userDomainsTable)
      .values({
        userId: req.user.id,
        domain: domain.toLowerCase(),
        verificationToken,
      })
      .returning();

    res.status(201).json(newDomain);
  } catch (err: any) {
    if (err.message.includes("unique constraint")) {
      return res.status(400).json({ error: "Domain already added" });
    }
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/domains/:id - Remove a domain
router.delete("/:id", authenticate, async (req: any, res) => {
  try {
    await db
      .delete(userDomainsTable)
      .where(
        and(
          eq(userDomainsTable.id, req.params.id),
          eq(userDomainsTable.userId, req.user.id)
        )
      );
    res.status(204).end();
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/domains/:id/verify - Verify ownership
router.post("/:id/verify", authenticate, async (req: any, res) => {
  try {
    const [domainRecord] = await db
      .select()
      .from(userDomainsTable)
      .where(
        and(
          eq(userDomainsTable.id, req.params.id),
          eq(userDomainsTable.userId, req.user.id)
        )
      );

    if (!domainRecord) {
      return res.status(404).json({ error: "Domain record not found" });
    }

    // Attempt HTTPS first, then fallback to HTTP
    const protocols = ["https", "http"];
    let verified = false;
    let lastError = "";

    for (const proto of protocols) {
      const url = `${proto}://${domainRecord.domain}/verify.txt`;
      try {
        const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
        if (response.ok) {
          const text = await response.text();
          if (text.trim() === domainRecord.verificationToken) {
            verified = true;
            break;
          } else {
            lastError = "Verification token mismatch";
          }
        } else {
          lastError = `Could not fetch verify.txt (HTTP ${response.status})`;
        }
      } catch (fetchErr: any) {
        lastError = fetchErr.message;
      }
    }

    if (verified) {
      await db
        .update(userDomainsTable)
        .set({ isVerified: true })
        .where(eq(userDomainsTable.id, domainRecord.id));
      return res.json({ success: true, message: "Domain verified successfully" });
    } else {
      return res.status(400).json({ error: `Verification failed: ${lastError}` });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
