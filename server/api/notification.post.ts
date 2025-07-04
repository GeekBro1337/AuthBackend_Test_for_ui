import { defineEventHandler, getHeader, createError, readBody } from 'h3'
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

  const body = await readBody(event)
  const { title, description, date, regular, regularDate } = body as Record<string, any>

  if (!title || !description || !date) {
    throw createError({ statusCode: 400, statusMessage: 'title, description и date обязательны' })
  }

  await prisma.notification.create({
    data: {
      forUser: user.name,
      title,
      description,
      date: new Date(date),
      regular: !!regular,
      regularDate: regularDate ? new Date(regularDate) : undefined
    }
  })

  const now = new Date()
  const notifications = await prisma.notification.findMany({
    where: {
      forUser: user.name,
      OR: [{ regular: true }, { date: { gte: now } }]
    }
  })

  return { notifications }
})
