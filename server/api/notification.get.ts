import { defineEventHandler, getHeader, createError } from 'h3'
import jwt from 'jsonwebtoken'
import prisma from '../utils/prisma'

export default defineEventHandler(async (event) => {
  const auth = getHeader(event, 'authorization')
  if (!auth?.startsWith('Bearer ')) {
    throw createError({ statusCode: 401, statusMessage: 'Нет токена' })
  }

  const token = auth.slice(7)
  const secret = process.env.JWT_SECRET
  if (!secret) {
    throw createError({ statusCode: 500, statusMessage: 'JWT_SECRET не задан' })
  }

  let payload: { userId: number }
  try {
    payload = jwt.verify(token, secret) as { userId: number }
  } catch {
    throw createError({ statusCode: 401, statusMessage: 'Недействительный токен' })
  }

  const user = await prisma.user.findUnique({ where: { id: payload.userId } })
  if (!user) {
    throw createError({ statusCode: 404, statusMessage: 'Пользователь не найден' })
  }

  const now = new Date()
  const notifications = await prisma.notification.findMany({
    where: {
      forUser: user.name,
      OR: [{ regular: true }, { date: { gte: now } }]
    }
  })

  return { notifications }
})
