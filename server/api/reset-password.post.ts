import { defineEventHandler, readBody, createError } from 'h3'
import bcrypt from 'bcryptjs'
import prisma from '../utils/prisma'

export default defineEventHandler(async (event) => {
  const { name, sa_password, newPassword } = await readBody(event)

  if (!name || !sa_password || !newPassword) {
    throw createError({ statusCode: 400, statusMessage: 'name, sa_password и newPassword обязательны' })
  }

  const saSecret = process.env.SA_PASSWORD
  if (!saSecret) {
    throw createError({ statusCode: 500, statusMessage: 'SA_PASSWORD не задан в .env' })
  }

  if (sa_password !== saSecret) {
    throw createError({ statusCode: 401, statusMessage: 'Недействительные данные' })
  }

  const user = await prisma.user.findUnique({ where: { name } })
  if (!user) {
    throw createError({ statusCode: 404, statusMessage: 'Пользователь не найден' })
  }

  const hashed = await bcrypt.hash(newPassword, 10)
  await prisma.user.update({ where: { id: user.id }, data: { password: hashed } })

  return { success: true }
})
