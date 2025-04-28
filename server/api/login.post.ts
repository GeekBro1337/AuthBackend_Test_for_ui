import { defineEventHandler, getHeader, createError } from 'h3'
import jwt from 'jsonwebtoken'
import prisma from '../utils/prisma'

export default defineEventHandler(async (event) => {
  const auth = getHeader(event, 'authorization') // читаем заголовок Authorization

  if (!auth || !auth.startsWith('Bearer ')) {
    throw createError({ statusCode: 401, statusMessage: 'Нет токена в заголовке Authorization' })
  }

  const token = auth.slice(7) // убираем "Bearer "
  const secret = process.env.JWT_SECRET

  if (!secret) {
    throw createError({ statusCode: 500, statusMessage: 'JWT_SECRET не задан в .env' })
  }

  let payload
  try {
    payload = jwt.verify(token, secret) as { userId: number }
  } catch (err) {
    throw createError({ statusCode: 401, statusMessage: 'Недействительный токен' })
  }

  const user = await prisma.user.findUnique({
    where: { id: payload.userId },
    select: { id: true, username: true, email: true }
  })

  if (!user) {
    throw createError({ statusCode: 404, statusMessage: 'Пользователь не найден' })
  }

  return { user }
})
