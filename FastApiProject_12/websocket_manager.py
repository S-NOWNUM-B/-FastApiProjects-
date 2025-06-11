from fastapi import WebSocket
from typing import List

class ConnectionManager:
    def __init__(self):
        # Список активных соединений
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        # Принимаем новое соединение
        await websocket.accept()
        # Добавляем его в список активных соединений
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        # Удаляем соединение из списка активных
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        # Отправляем сообщение всем активным соединениям
        for connection in self.active_connections:
            await connection.send_text(message) 