# Auth Backend Test

Простой сервер на Nuxt 3 с примерами эндпоинтов для регистрации и авторизации пользователей.  
Сервис использует PostgreSQL через Prisma и выдает JWT‑токены.

## Быстрый старт

1. Установите зависимости

```bash
pnpm install
```

2. Скопируйте `.envExemple` в `.env` и при необходимости измените значения.
   В файле есть переменная `SA_PASSWORD` – общий пароль администратора, 
   необходимый для сброса пароля пользователей.

```bash
cp .envExemple .env
```

3. Запустите базу данных (пример есть в `DB/docker-compose.yml`)

```bash
docker compose -f DB/docker-compose.yml up -d
```

4. Запустите приложение

```bash
pnpm dev
```

По умолчанию сервер будет доступен на `http://localhost:4001`.

## API

Все маршруты находятся под префиксом `/api`.

### POST `/api/register`

Создание нового пользователя.

**Тело запроса**

```json
{
  "name": "username",
  "password": "password123"
}
```

**Ответ**

```json
{
  "name": "username",
  "role": "guest",
  "token": "<jwt>"
}
```

### POST `/api/login`

Авторизация существующего пользователя.

**Тело запроса**

```json
{
  "name": "username",
  "password": "password123"
}
```

**Ответ** – структура такая же, как у `register`.

### POST `/api/reset-password`

Сброс пароля администраторами. Требуется знание переменной `SA_PASSWORD`.

**Тело запроса**

```json
{
  "name": "username",
  "sa_password": "admin-secret",
  "newPassword": "newpass123"
}
```

**Ответ**

```json
{ "success": true }
```

### GET `/api/me`

Получение информации о текущем пользователе. Требуется заголовок

```
Authorization: Bearer <jwt>
```

**Ответ**

```json
{
  "user": { "id": 1, "name": "username", "role": "guest" }
}
```

## Миграции базы данных

Для применения схемы выполните:

```bash
npx prisma migrate deploy
```

## Разработка и сборка

Дополнительные команды находятся в `package.json`:

- `pnpm dev` – запуск в режиме разработки;
- `pnpm build` – сборка проекта;
- `pnpm preview` – предпросмотр собранного проекта.

