from celery import Celery
import time

celery_app = Celery(
    "tasks",
    broker="redis://redis:6379/0",
    backend="redis://redis:6379/0"
)

@celery_app.task
def send_mock_email(email: str):
    time.sleep(10)
    print(f"Email sent to {email}")
    return {"status": "success", "message": f"Email sent to {email}"} 