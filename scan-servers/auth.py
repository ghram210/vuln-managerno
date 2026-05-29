import httpx
from fastapi import Header, HTTPException
from config import SUPABASE_URL, SUPABASE_SERVICE_KEY

ADMIN_EMAILS = [
    "jehanmoshle@gmail.com",
    "gharamrahal6@gmail.com",
]

async def get_authenticated_user(authorization: str = Header(None)) -> dict:
    """
    Authenticates the user via Supabase and determines their role.
    Returns: {"id": str, "email": str, "role": "admin" | "user"}
    """
    if not authorization:
        print("[auth] Missing Authorization header")
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = authorization.replace("Bearer ", "").strip()
    if not token:
        print("[auth] Empty token")
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{SUPABASE_URL}/auth/v1/user",
                headers={
                    "Authorization": f"Bearer {token}",
                    "apikey": SUPABASE_SERVICE_KEY,
                },
                timeout=10,
            )

        if resp.status_code != 200:
            print(f"[auth] Supabase auth failed: {resp.status_code} {resp.text}")
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        user = resp.json()
        user_id = user.get("id")
        user_email = (user.get("email") or "").strip().lower()

        if not user_id:
            print("[auth] No user ID in Supabase response")
            raise HTTPException(status_code=401, detail="Invalid user")

        role = "user" # Default role

        # Check 1: Hardcoded admin list
        if user_email in ADMIN_EMAILS:
            role = "admin"
            print(f"[auth] User {user_email} is admin (hardcoded)")

        # Check 2: user_roles table
        if role != "admin":
            async with httpx.AsyncClient() as client:
                ur_resp = await client.get(
                    f"{SUPABASE_URL}/rest/v1/user_roles",
                    params={"user_id": f"eq.{user_id}", "select": "role"},
                    headers={
                        "apikey": SUPABASE_SERVICE_KEY,
                        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                    },
                    timeout=10,
                )

            if ur_resp.status_code == 200:
                data = ur_resp.json()
                if data and isinstance(data, list) and len(data) > 0:
                    db_role = str(data[0].get("role", "")).lower()
                    if db_role == "admin":
                        role = "admin"
                        print(f"[auth] User {user_email} is admin (user_roles)")

        # Check 3: admin_users table
        if role != "admin" and user_email:
            async with httpx.AsyncClient() as client:
                role_resp = await client.get(
                    f"{SUPABASE_URL}/rest/v1/admin_users",
                    params={"email": f"ilike.{user_email}", "select": "role"},
                    headers={
                        "apikey": SUPABASE_SERVICE_KEY,
                        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                    },
                    timeout=10,
                )

            if role_resp.status_code == 200:
                data = role_resp.json()
                if data and isinstance(data, list) and len(data) > 0:
                    db_role = str(data[0].get("role", "")).lower()
                    if db_role == "admin":
                        role = "admin"
                        print(f"[auth] User {user_email} is admin (admin_users)")

        return {"id": user_id, "email": user_email, "role": role}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[auth] Unexpected error during authentication: {e}")
        raise HTTPException(status_code=500, detail=f"Internal authentication error: {str(e)}")


async def get_admin_user(authorization: str = Header(None)) -> dict:
    """
    Deprecated: preserved for compatibility but enforces admin role.
    """
    user = await get_authenticated_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
