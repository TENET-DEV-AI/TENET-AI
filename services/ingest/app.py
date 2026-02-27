"""
TENET AI - Ingest Service
Middleware layer for intercepting and processing LLM requests.
"""
import os
import uuid
import logging
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as redis

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))
API_KEY = os.getenv("API_KEY", "tenet-dev-key-change-in-production")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

# FastAPI app
app = FastAPI(
    title="TENET AI - Ingest Service",
    description="Security middleware for LLM applications",
    version="0.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis connection
redis_client: Optional[redis.Redis] = None


# Request/Response Models
class LLMEventRequest(BaseModel):
    """Incoming LLM event for security analysis."""
    source_type: str = Field(..., description="Type of source: chat, agent, api, etc.")
    source_id: str = Field(..., description="Unique identifier for the source")
    model: str = Field(..., description="LLM model being used")
    prompt: str = Field(..., description="The prompt to analyze")
    system_prompt: Optional[str] = Field(None, description="System prompt if available")
    metadata: Optional[dict] = Field(default_factory=dict)


class LLMEventResponse(BaseModel):
    """Response after processing LLM event."""
    event_id: str
    timestamp: str
    blocked: bool = False
    sanitized: bool = False
    risk_score: float = 0.0
    verdict: str = "pending"
    message: str = "Event queued for analysis"


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str
    version: str
    redis_connected: bool


@app.on_event("startup")
async def startup():
    """Initialize connections on startup."""
    global redis_client
    try:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True
        )
        await redis_client.ping()
        logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        redis_client = None


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    global redis_client
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed")


def verify_api_key(x_api_key: str = Header(...)):
    """Verify API key for authentication."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    redis_connected = False
    if redis_client:
        try:
            await redis_client.ping()
            redis_connected = True
        except Exception:
            pass
    
    return HealthResponse(
        status="healthy" if redis_connected else "degraded",
        service="ingest",
        version="0.1.0",
        redis_connected=redis_connected
    )


@app.post("/v1/events/llm", response_model=LLMEventResponse)
async def ingest_llm_event(
    request: LLMEventRequest,
    x_api_key: str = Header(...)
):
    """
    Ingest an LLM event for security analysis.
    
    This endpoint receives prompts before they are sent to the LLM,
    queues them for analysis, and returns immediate blocking decisions
    for known malicious patterns.
    """
    verify_api_key(x_api_key)
    
    # Generate event ID
    event_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    
    # Quick heuristic check for immediate blocking
    blocked, risk_score, verdict = quick_heuristic_check(request.prompt)
    
    # Create event payload
    event_payload = {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_type": request.source_type,
        "source_id": request.source_id,
        "model": request.model,
        "prompt": request.prompt,
        "system_prompt": request.system_prompt,
        "metadata": request.metadata,
        "blocked": blocked,
        "risk_score": risk_score,
        "verdict": verdict
    }
    
    # Queue for detailed analysis if not immediately blocked
    if redis_client and not blocked:
        try:
            import json
            await redis_client.lpush("tenet:events:queue", json.dumps(event_payload))
            await redis_client.set(f"tenet:event:{event_id}", json.dumps(event_payload), ex=86400)
            logger.info(f"Event {event_id} queued for analysis")
        except Exception as e:
            logger.error(f"Failed to queue event: {e}")
    
    return LLMEventResponse(
        event_id=event_id,
        timestamp=timestamp,
        blocked=blocked,
        risk_score=risk_score,
        verdict=verdict,
        message="Blocked - malicious pattern detected" if blocked else "Event queued for analysis"
    )


def quick_heuristic_check(prompt: str) -> tuple[bool, float, str]:
    """
    Quick heuristic check for known malicious patterns.
    Returns (blocked, risk_score, verdict).
    """
    prompt_lower = prompt.lower()
    
    # High-risk prompt injection patterns
    injection_patterns = [
        "ignore previous instructions",
        "ignore all previous",
        "disregard your instructions",
        "forget your system prompt",
        "you are now",
        "from now on you are",
        "new persona:",
        "jailbreak mode",
        "dan mode",
        "developer mode enabled",
        "simulate being",
        "</s>",
        "<|system|>",
        "system prompt:",
        "reveal your instructions"
    ]
    
    # Jailbreak patterns
    jailbreak_patterns = [
        "do anything now",
        "no restrictions",
        "without any limitations",
        "bypass your programming",
        "override your safety",
        "pretend you have no rules",
        "act as an unrestricted ai",
        "evil mode",
        "chaos mode"
    ]
    
    # Data extraction patterns
    extraction_patterns = [
        "show me your system prompt",
        "what are your instructions",
        "reveal your training data",
        "show examples from training",
        "list your rules",
        "what's in your system message"
    ]
    
    # Check patterns
    for pattern in injection_patterns:
        if pattern in prompt_lower:
            return True, 0.95, "malicious"
    
    for pattern in jailbreak_patterns:
        if pattern in prompt_lower:
            return True, 0.90, "malicious"
    
    for pattern in extraction_patterns:
        if pattern in prompt_lower:
            return False, 0.75, "suspicious"
    
    return False, 0.0, "benign"


@app.get("/v1/events")
async def list_events(
    limit: int = 50,
    offset: int = 0,
    x_api_key: str = Header(...)
):
    """
    List historical events for the dashboard.
    """
    verify_api_key(x_api_key)
    
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    
    try:
        import json
        # In a real app, we'd use a database like Postgres for this.
        # For the prototype, we use Redis keys.
        keys = await redis_client.keys("tenet:event:*")
        # Sort keys to get latest first (event IDs are UUIDs, so we should look at timestamps)
        
        events = []
        for key in keys:
            data = await redis_client.get(key)
            if data:
                events.append(json.loads(data))
        
        # Sort by timestamp descending
        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return {
            "total": len(events),
            "limit": limit,
            "offset": offset,
            "events": events[offset : offset + limit]
        }
    except Exception as e:
        logger.error(f"Failed to list events: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/v1/stats")
async def get_stats(x_api_key: str = Header(...)):
    """
    Get summary statistics for the dashboard.
    """
    verify_api_key(x_api_key)
    
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    
    try:
        import json
        keys = await redis_client.keys("tenet:event:*")
        
        total_events = len(keys)
        blocked_count = 0
        threat_counts = {
            "malicious": 0,
            "suspicious": 0,
            "benign": 0
        }
        
        for key in keys:
            data = await redis_client.get(key)
            if data:
                event = json.loads(data)
                if event.get("blocked"):
                    blocked_count += 1
                
                verdict = event.get("verdict", "benign")
                threat_counts[verdict] = threat_counts.get(verdict, 0) + 1
        
        return {
            "total_events": total_events,
            "blocked_count": blocked_count,
            "threat_distribution": threat_counts,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
