import os
import redis.asyncio as aioredis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

async def get_redis() -> aioredis.Redis:
    redis = await aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    try:
        yield redis
    finally:
        await redis.close()

CACHE_TTL = 300
NOTES_CACHE_PREFIX = "notes:" 