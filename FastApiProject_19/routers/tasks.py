from celery import Celery
import time

celery_app = Celery(
    "tasks",
    broker="redis://redis:6379/0",
    backend="redis://redis:6379/0"
)

@celery_app.task(
    name="send_mock_email",
    description="Отправляет тестовое email-сообщение указанному пользователю",
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def send_mock_email(self, email: str):
    """
    Отправляет тестовое email-сообщение.
    
    Args:
        email (str): Email-адрес получателя
        
    Returns:
        dict: Статус отправки сообщения
        
    Raises:
        Exception: При ошибке отправки
    """
    try:
        time.sleep(10)  # Имитация отправки
        print(f"Email sent to {email}")
        return {"status": "success", "message": f"Email sent to {email}"}
    except Exception as exc:
        self.retry(exc=exc) 