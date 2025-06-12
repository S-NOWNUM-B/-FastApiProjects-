from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from websocket_manager import ConnectionManager

router = APIRouter(
    tags=["WebSocket"],
    responses={
        400: {
            "description": "Ошибка подключения к WebSocket",
            "content": {
                "application/json": {
                    "example": {"detail": "WebSocket connection error"}
                }
            }
        }
    }
)

manager = ConnectionManager()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket соединение для обмена сообщениями в реальном времени.
    
    Поддерживает подключение нескольких клиентов и широковещательную рассылку сообщений.
    """
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(f"Сообщение: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast("Клиент отключился") 