import { defineEventHandler, readBody, createError } from 'h3'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import prisma from '../utils/prisma'

export default defineEventHandler(async (event) => {
  // 1. Читаем входные данные
  const { email, password, username } = await readBody(event)

  // 2. Быстрая валидация
  if (!email || !password || !username) {
    throw createError({ statusCode: 400, statusMessage: 'email, password, username обязательны' })
  }

  // 3. Проверяем, нет ли уже такого email
  const exists = await prisma.user.findUnique({ where: { email } })
  if (exists) {
    throw createError({ statusCode: 409, statusMessage: 'Пользователь уже существует' })
  }

  // 4. Хешируем пароль
  const hashed = await bcrypt.hash(password, 10)

  // 5. Создаём пользователя
  const user = await prisma.user.create({
    data: { email, username, password: hashed }
  })

  // 6. Генерируем токен
  const secret = process.env.JWT_SECRET
  if (!secret) {
    throw createError({ statusCode: 500, statusMessage: 'JWT_SECRET не задан в .env' })
  }

  const token = jwt.sign({ userId: user.id }, secret, { expiresIn: '7d' })

  // 7. Отдаём ответ
  return {
    user: { id: user.id, username: user.username, email: user.email },
    token
  }
})
