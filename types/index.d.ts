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
