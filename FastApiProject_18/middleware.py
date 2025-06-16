import time
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from .logger import logger
from redis.asyncio import Redis
from config import settings

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        logger.info(
            "Request processed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "process_time": process_time
            }
        )
        
        return response 

class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis: Redis):
        super().__init__(app)
        self.redis = redis

    async def dispatch(self, request: Request, call_next):
        client_id = request.client.host
        key = f"{settings.RATE_LIMIT_PREFIX}{client_id}"
        
        async with self.redis.pipeline() as pipe:
            try:
                current = await pipe.incr(key).execute()
                if current == 1:
                    await pipe.expire(key, settings.RATE_LIMIT_WINDOW).execute()
                
                if current > settings.RATE_LIMIT_REQUESTS:
                    raise HTTPException(
                        status_code=429,
                        detail="Too many requests. Please try again later."
                    )
                
                response = await call_next(request)
                return response
                
            except Exception as e:
                if isinstance(e, HTTPException):
                    raise e
                raise HTTPException(
                    status_code=500,
                    detail="Internal server error"
                ) 