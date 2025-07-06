import { defineEventHandler, readBody, createError } from 'h3'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import prisma from '../utils/prisma'

export default defineEventHandler(async (event) => {
  const { name, password } = await readBody(event)

  if (!name || !password) {
    throw createError({ statusCode: 400, statusMessage: 'name и password обязательны' })
  }

  const user = await prisma.user.findUnique({ where: { name } })

  if (!user || !user.password) {
    throw createError({ statusCode: 401, statusMessage: 'Неверные учётные данные' })
  }

  const valid = await bcrypt.compare(password, user.password)

  if (!valid) {
    throw createError({ statusCode: 401, statusMessage: 'Неверные учётные данные' })
  }

  const secret = process.env.JWT_SECRET

  if (!secret) {
    throw createError({ statusCode: 500, statusMessage: 'JWT_SECRET не задан в .env' })
  }

  const token = jwt.sign({ userId: user.id }, secret, { expiresIn: '7d' })

  return {
    name: user.name,
    role: user.role,
    token
  }
})
