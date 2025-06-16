# FastAPI: Автоматическое Развертывание с GitHub Actions

REST API с расширенным CI/CD пайплайном, использующим **GitHub Actions** для автоматического тестирования, сборки Docker-образа и развертывания на платформе **Render**, построенное на **FastAPI** и контейнеризированное с помощью **Docker**. Проект демонстрирует настройку непрерывного развертывания (CD) с публикацией образа в **Docker Hub** и автоматическим обновлением приложения.

## Описание

Проект выполнен в рамках задания №20 по расширению CI/CD пайплайна для автоматического развертывания FastAPI-приложения. Основной функционал включает:

- Настройку платформы **Render** для хостинга приложения и базы данных **PostgreSQL**.
- Публикацию Docker-образа в **Docker Hub** через GitHub Actions.
- Автоматическое развертывание приложения на Render после успешного прохождения тестов.
- Использование переменных окружения и секретов для безопасной конфигурации.
- Тестирование процесса развертывания с проверкой обновлений API.

## ⚙️ Используемые технологии

- **FastAPI** — высокопроизводительный фреймворк для создания API.
- **GitHub Actions** — платформа для CI/CD.
- **Docker** / **Docker Compose** — контейнеризация и оркестрация.
- **Docker Hub** — реестр для хранения Docker-образов.
- **Render** — платформа для хостинга приложения и базы данных.
- **PostgreSQL** — реляционная база данных для хранения данных.
- **pytest** — инструмент для автоматизированного тестирования.
- **Uvicorn** — ASGI-сервер для запуска FastAPI-приложения.

## 🚀 Установка и запуск

### 1. Локальный запуск (для разработки)

1. Убедитесь, что **Docker**, **Docker Desktop** и **PostgreSQL** установлены.
2. Создайте файл `.env` в корне проекта (пример в разделе "Особенности").
3. Активируйте виртуальное окружение и установите зависимости:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Для Linux/macOS
   .venv\Scripts\activate     # Для Windows
   pip install -r requirements.txt
   ```

4. Запустите сервер:
   ```bash
   uvicorn main:app --reload
   ```

### 2. Запуск через Docker

1. Создайте файл `.env` и добавьте его в `.gitignore`.
2. Соберите и запустите контейнеры:
   ```bash
   docker compose up --build
   ```

3. API будет доступен:  
   - **API**: [http://localhost:8000](http://localhost:8000)  
   - **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)  
   - **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

## 🧪 Тестирование CI/CD

### 1. Настройка Render

1. Зарегистрируйтесь на [Render](https://render.com) и создайте новое приложение:
   - Выберите "Web Service" и подключите ваш GitHub-репозиторий.
   - Укажите Docker как runtime и настройте порт (8000).
2. Создайте базу данных PostgreSQL в Render:
   - Скопируйте `Internal Database URL` для использования в переменных окружения.
3. Настройте переменные окружения в Render Dashboard:
   ```bash
   DATABASE_URL=postgresql+asyncpg://<user>:<password>@<host>:<port>/<dbname>
   SECRET_KEY=your_secret_key_here
   REDIS_URL=redis://redis:6379/0
   ```
4. Получите API-ключ Render:
   - Перейдите в Account Settings → API Keys и создайте ключ.
   - Сохраните его для использования в GitHub Secrets.

### 2. Настройка Docker Hub

1. Зарегистрируйтесь на [Docker Hub](https://hub.docker.com).
2. Создайте репозиторий (например, `your_username/fastapi-app`).
3. Добавьте секреты в GitHub репозитории:
   - Перейдите в Settings → Secrets and variables → Actions.
   - Добавьте:
     - `DOCKERHUB_USERNAME`: ваш логин Docker Hub.
     - `DOCKERHUB_TOKEN`: токен доступа Docker Hub.
     - `RENDER_API_KEY`: API-ключ Render.
     - `SECRET_KEY`: секретный ключ для JWT.

### 3. Обновление GitHub Actions

Обновите файл `.github/workflows/ci.yml`:
```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches:
      - main

jobs:
  build_and_test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:latest
        env:
          POSTGRES_DB: test_notesdb
          POSTGRES_USER: username
          POSTGRES_PASSWORD: password
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:latest
        ports:
          - 6379:6379

    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run Tests
        env:
          DATABASE_URL: postgresql+asyncpg://username:password@localhost:5432/test_notesdb
          REDIS_URL: redis://localhost:6379/0
          SECRET_KEY: ${{ secrets.SECRET_KEY }}
        run: pytest test_main.py

      - name: Build Docker Image
        run: docker build . -t ${{ secrets.DOCKERHUB_USERNAME }}/fastapi-app:latest

      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Push Docker Image
        run: docker push ${{ secrets.DOCKERHUB_USERNAME }}/fastapi-app:latest

  deploy:
    runs-on: ubuntu-latest
    needs: build_and_test
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Deploy to Render
        env:
          RENDER_API_KEY: ${{ secrets.RENDER_API_KEY }}
          RENDER_SERVICE_ID: <your_render_service_id>
        run: |
          curl -X POST \
          -H "Authorization: Bearer $RENDER_API_KEY" \
          -H "Content-Type: application/json" \
          -d '{"image": "${{ secrets.DOCKERHUB_USERNAME }}/fastapi-app:latest"}' \
          https://api.render.com/v1/services/$RENDER_SERVICE_ID/deploys
```

**Примечание**: Замените `<your_render_service_id>` на ID вашего сервиса Render (доступен в Dashboard).

### 4. Тестирование развертывания

1. Внесите изменение в код, например, измените ответ эндпоинта `/health`:
   ```python
   @app.get("/health")
   async def health_check():
       return {"status": "healthy", "message": "API is running (v2)"}
   ```

2. Отправьте изменения в ветку `main`:
   ```bash
   git add .
   git commit -m "Update health check message"
   git push origin main
   ```

3. Перейдите во вкладку **Actions** в GitHub репозитории:
   - Наблюдайте за выполнением пайплайна (`build_and_test` и `deploy`).
   - Убедитесь, что тесты, сборка образа, публикация в Docker Hub и развертывание на Render проходят успешно.

4. Проверьте развернутое приложение:
   - Откройте URL вашего приложения на Render (например, `https://your-app.onrender.com`).
   - Выполните запрос:
     ```
     GET https://your-app.onrender.com/health
     ```
     Ожидаемый ответ:
     ```json
     {"status": "healthy", "message": "API is running (v2)"}
     ```

### Возможные ошибки и их решение

- **Tests fail in CI**: Проверьте, что `DATABASE_URL` и сервисы в `ci.yml` настроены корректно.
- **Docker Hub push fails**: Убедитесь, что `DOCKERHUB_USERNAME` и `DOCKERHUB_TOKEN` заданы в GitHub Secrets.
- **Render deployment fails**: Проверьте `RENDER_API_KEY` и `RENDER_SERVICE_ID` в `ci.yml`.
- **Application not updated**: Убедитесь, что Render использует правильный тег образа (`latest`) и переменные окружения синхронизированы.

## 🧫 Примеры использования (через Postman)

### 📌 Проверка состояния `GET /health`
- **Метод**: GET
- **URL**: `https://your-app.onrender.com/health`
- **Ответ** (JSON):
  ```json
  {"status": "healthy", "message": "API is running (v2)"}
  ```

### 📒 Получение заметок `GET /notes`
- **Метод**: GET
- **URL**: `https://your-app.onrender.com/notes?skip=0&limit=10`
- **Заголовки**:
  ```
  Authorization: Bearer <JWT-токен>
  ```
- **Ответ** (JSON):
  ```json
  [
    {
      "id": 1,
      "text": "Тестовая заметка",
      "owner_id": 1,
      "created_at": "2025-06-12T05:51:00+05:00"
    }
  ]
  ```

## 🧾 Особенности

- **CI/CD пайплайн**: Автоматически тестирует, собирает и публикует Docker-образ, затем развертывает приложение на Render.
- **Render**: Обеспечивает хостинг приложения и PostgreSQL с автоматическим масштабированием.
- **Docker Hub**: Хранит Docker-образы с тегом `latest` для каждого успешного коммита.
- **Безопасность**: Конфиденциальные данные хранятся в GitHub Secrets и переменных окружения Render.
- **Рекомендация**: Настройте мониторинг (например, Prometheus из Задания 17) для отслеживания производительности на Render.

## 📦 Контейнеры

Конфигурация **Docker Compose** для локального тестирования включает два сервиса:

```yaml
# docker-compose.yml
services:
  web:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env
    environment:
      - DATABASE_URL=postgresql+asyncpg://username:password@db:5432/notesdb
    depends_on:
      - db

  db:
    image: postgres
    environment:
      POSTGRES_DB: notesdb
      POSTGRES_USER: username
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## 🗂️ Документация

- **Swagger UI**: [https://your-app.onrender.com/docs](https://your-app.onrender.com/docs)  
- **ReDoc**: [https://your-app.onrender.com/redoc](https://your-app.onrender.com/redoc)

## Контакты

Если вам нужна помощь с проектом или есть вопросы, пишите в **Microsoft Teams**.