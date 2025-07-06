export interface User {
  id: number
  name: string
  role: string
}

export interface AuthResult {
  name: string
  role: string
  token: string
}

export interface ResetPasswordBody {
  name: string
  sa_password: string
  newPassword: string
}

export interface Notification {
  id: number
  forUser: string
  title: string
  description: string
  date: string
  regular: boolean
  regularDate?: string
  createdAt: string
}
