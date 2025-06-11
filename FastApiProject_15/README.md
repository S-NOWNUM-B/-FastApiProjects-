# FastAPI: Настройка CI/CD с GitHub Actions

REST API с настроенным CI/CD пайплайном, использующим **GitHub Actions** для автоматического запуска тестов и сборки Docker-образа при каждом push в репозиторий. Проект демонстрирует интеграцию тестирования, контейнеризации и деплоя для FastAPI-приложения с использованием **Docker**, **pytest**, **PostgreSQL** и **Redis**.

## Описание

Проект выполнен в рамках задания №15 по настройке CI/CD пайплайна с использованием **GitHub Actions**. Основной функционал включает:

- Создание workflow для автоматического запуска тестов и сборки Docker-образа.
- Интеграцию с **PostgreSQL** и **Redis** для тестирования в изолированной среде.
- Автоматическую сборку и (опционально) публикацию Docker-образа в Docker Hub.
- Тестирование пайплайна через GitHub Actions с проверкой успешного выполнения всех шагов.

## ⚙️ Используемые технологии

- **FastAPI** — высокопроизводительный фреймворк для создания API.
- **pytest** — инструмент для автоматизированного тестирования.
- **Docker** / **Docker Compose** — контейнеризация и оркестрация.
- **GitHub Actions** — платформа для CI/CD.
- **PostgreSQL** — реляционная база данных для хранения данных.
- **Redis** — хранилище для кеширования или фоновых задач.
- **Uvicorn** — ASGI-сервер для запуска FastAPI-приложения.

## 🚀 Установка и запуск

### 1. Локальный запуск (для разработки)

1. Убедитесь, что **Docker**, **Docker Desktop**, **PostgreSQL** и **Redis** установлены.
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

### 1. Настройка GitHub Actions

1. Создайте файл `.github/workflows/ci.yml` в корне проекта:
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
        run: docker build . -t your_dockerhub_username/fastapi-app:latest

      - name: Login to Docker Hub
        if: success()
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Push Docker Image
        if: success()
        run: docker push your_dockerhub_username/fastapi-app:latest
```

2. Настройте секреты в GitHub:
   - Перейдите в репозиторий → Settings → Secrets and variables → Actions.
   - Добавьте секреты: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `SECRET_KEY`.

### 2. Тестирование пайплайна

1. Отправьте изменения в ветку `main`:
   ```bash
   git add .
   git commit -m "Add CI/CD pipeline"
   git push origin main
   ```

2. Перейдите во вкладку **Actions** в GitHub репозитории.
3. Наблюдайте за выполнением пайплайна:
   - Убедитесь, что шаги (Checkout, Setup Python, Install Dependencies, Run Tests, Build Docker Image, Push Docker Image) проходят успешно.
4. Внесите небольшое изменение в код (например, добавьте комментарий), сделайте push и проверьте, что пайплайн снова запускается.

### Возможные ошибки и их решение

- **Tests fail due to database connection**: Убедитесь, что `DATABASE_URL` в `ci.yml` совпадает с настройками сервиса `postgres`.
- **Docker build fails**: Проверьте синтаксис `Dockerfile` и наличие всех зависимостей в `requirements.txt`.
- **Docker Hub login error**: Убедитесь, что секреты `DOCKERHUB_USERNAME` и `DOCKERHUB_TOKEN` настроены корректно в GitHub.
- **Tests timeout**: Увеличьте `health-interval` или `health-timeout` в сервисе `postgres` в `ci.yml`.

## 🧫 Примеры использования (через Postman)

### 📒 Получение заметок `GET /notes`
- **Метод**: GET
- **URL**: `/notes?skip=0&limit=10`
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
      "created_at": "2025-06-12T01:12:00+05:00"
    }
  ]
  ```

### 📌 Создание заметки `POST /notes`
- **Метод**: POST
- **URL**: `/notes`
- **Заголовки**:
  ```
  Authorization: Bearer <JWT-токен>
  Content-Type: application/json
  ```
- **Тело запроса** (JSON):
  ```json
  {
    "text": "Новая заметка"
  }
  ```
- **Ответ** (JSON):
  ```json
  {
    "id": 1,
    "text": "Новая заметка",
    "owner_id": 1,
    "created_at": "2025-06-12T01:12:00+05:00"
  }
  ```

## 🧾 Особенности

- **CI/CD пайплайн**: Автоматически запускает тесты и собирает Docker-образ при push в `main`.
- **Тестирование**: Тесты выполняются в изолированной среде с **PostgreSQL** и **Redis** через GitHub Actions services.
- **Контейнеризация**: Docker-образ собирается и (опционально) публикуется в Docker Hub.
- **Безопасность**: Конфиденциальные данные (`SECRET_KEY`, `DOCKERHUB_TOKEN`) хранятся в GitHub Secrets.
- **Логирование**: Логи GitHub Actions помогают отслеживать выполнение каждого шага.

## 📦 Контейнеры

Конфигурация **Docker Compose** включает три сервиса:

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
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

  db:
    image: postgres
    environment:
      POSTGRES_DB: notesdb
      POSTGRES_USER: username
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:latest
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

## 🗂️ Документация

- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)  
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

## Контакты

Если вам нужна помощь с проектом или есть вопросы, пишите в **Microsoft Teams**.