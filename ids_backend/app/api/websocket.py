from fastapi import WebSocket
import asyncio
from typing import Set

connections: Set[WebSocket] = set()

async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connections.add(ws)

    try:
        while True:
            await asyncio.sleep(60)
    finally:
        connections.discard(ws)  # safer than remove()

async def broadcast(message: dict):
    for ws in list(connections):
        try:
            await ws.send_json(message)
        except Exception:
            connections.discard(ws)
