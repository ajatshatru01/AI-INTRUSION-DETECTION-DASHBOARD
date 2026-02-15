from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from app.models.loader import load_models
from app.api.routes import router
from app.api.websocket import websocket_endpoint

app = FastAPI(title="Real-Time IDS (Stateless)")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for dev; restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await websocket_endpoint(ws)

@app.on_event("startup")
async def startup():
    load_models()


