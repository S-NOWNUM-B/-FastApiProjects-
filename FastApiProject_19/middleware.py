import time
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from logger import logger
from redis.asyncio import Redis
from config import settings

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        logger.info(f"{request.method} {request.url.path} completed in {process_time:.2f}s")
        
        return response 

class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis):
        super().__init__(app)
        self.redis = redis

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        key = f"rate_limit:{client_ip}"
        
        current = await self.redis.get(key)
        if current is None:
            await self.redis.set(key, 1, ex=60)
        elif int(current) >= 100:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return HTTPException(
                status_code=429,
                detail="Too many requests. Please try again later."
            )
        else:
            await self.redis.incr(key)
            
        return await call_next(request) 