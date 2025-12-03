import React from 'react'
import { api } from './lib/api.js'
import LoginForm from './auth/LoginForm.jsx'
import RegisterForm from './auth/RegisterForm.jsx'
import UsersTable from './features/users/UsersTable.jsx'

export default function App() {
  const [me, setMe] = React.useState(null)
  const [error, setError] = React.useState('')
  const [loading, setLoading] = React.useState(true)
  const envLabel = (import.meta.env.VITE_APP_ENV || import.meta.env.MODE || 'development').toLowerCase()
  const headingEnv = envLabel === 'stage' ? 'Stage' : envLabel === 'production' ? 'Production' : 'Dev'

  const refreshMe = React.useCallback(() => {
    setLoading(true)
    api('/api/me')
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setLoading(false))
  }, [])

  React.useEffect(() => { refreshMe() }, [refreshMe])

  const onLogin = async (username, password) => {
    setError('')
    try {
      await api('/api/login', { method: 'POST', body: { username, password } })
      refreshMe()
    } catch (e) { setError(e.message) }
  }

  const onRegister = async (username, password) => {
    setError('')
    try {
      await api('/api/register', { method: 'POST', body: { username, password } })
      await onLogin(username, password)
    } catch (e) { setError(e.message) }
  }

  const onLogout = async () => {
    await api('/api/logout', { method: 'POST' })
    setMe(null)
  }

  return (
    <div style={{ maxWidth: 900, margin: '40px auto', padding: 16 }}>
      <h1>Проста аутентифікація (React + Go) {headingEnv}</h1>
      {loading ? (
        <p>Завантаження...</p>
      ) : me ? (
        <div style={{ marginBottom: 24 }}>
          <p>Ви увійшли як <strong>{me.username}</strong></p>
          <button onClick={onLogout}>Вийти</button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
          <LoginForm onSubmit={onLogin} />
          <RegisterForm onSubmit={onRegister} />
        </div>
      )}

      {error && (
        <div style={{ color: '#b00020', marginTop: 12 }}>
          <strong>Помилка:</strong> {error}
        </div>
      )}

      <hr style={{ margin: '24px 0' }} />

      <h2>Список користувачів (захищений ендпоінт)</h2>
      <UsersTable isAuthed={!!me} />

      <footer style={{ marginTop: 32, color: '#777' }}>
        <small>Dev: фронт :5173 (Vite), бек :8080 (Gin) • JWT</small>
      </footer>
    </div>
  )
}
