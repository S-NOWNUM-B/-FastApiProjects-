from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from websocket_manager import ConnectionManager

router = APIRouter()
manager = ConnectionManager()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Принимаем новое соединение
    await manager.connect(websocket)
    try:
        while True:
            # Получаем сообщение от клиента
            data = await websocket.receive_text()
            # Отправляем сообщение всем подключенным клиентам
            await manager.broadcast(f"Сообщение: {data}")
    except WebSocketDisconnect:
        # При отключении клиента удаляем его из менеджера
        manager.disconnect(websocket)
        # Уведомляем остальных клиентов об отключении
        await manager.broadcast("Клиент отключился") 