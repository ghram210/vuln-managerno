import httpx
from fastapi import Header, HTTPException
from config import SUPABASE_URL, SUPABASE_SERVICE_KEY


async def get_authenticated_user(authorization: str = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = authorization.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Invalid token")

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
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = resp.json()
    user_id = user.get("id")
    user_email = (user.get("email") or "").strip()

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user")

    # Fetch role from user_roles table
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

    role = "user"
    if ur_resp.status_code == 200 and ur_resp.json():
        role = str(ur_resp.json()[0].get("role", "user")).lower()

    return {"id": user_id, "email": user_email, "role": role}

async def get_admin_user(authorization: str = Header(None)) -> dict:
    user = await get_authenticated_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
