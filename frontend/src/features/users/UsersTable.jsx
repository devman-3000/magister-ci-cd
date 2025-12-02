import React from 'react'
import { api } from '../../lib/api.js'

export default function UsersTable({ isAuthed }) {
  const [data, setData] = React.useState([])
  const [error, setError] = React.useState('')
  const [loading, setLoading] = React.useState(false)

  React.useEffect(() => {
    if (!isAuthed) { setData([]); return }
    let cancelled = false
    setLoading(true)
    api('/api/users')
      .then((users) => { if (!cancelled) setData(users) })
      .catch((e) => { if (!cancelled) setError(e.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [isAuthed])

  if (!isAuthed) return <div>Увійдіть, щоб побачити список користувачів.</div>
  if (loading) return <div>Завантаження…</div>
  if (error) return <div style={{ color: '#b00020' }}>Помилка: {error}</div>
  if (!data.length) return <div>Користувачів не знайдено.</div>

  const th = { textAlign: 'left', borderBottom: '1px solid #ddd', padding: '8px' }
  const td = { borderBottom: '1px solid #f0f0f0', padding: '8px' }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={th}>ID</th>
            <th style={th}>Username</th>
          </tr>
        </thead>
        <tbody>
          {data.map((u) => (
            <tr key={u.id}>
              <td style={td}>{u.id}</td>
              <td style={td}>{u.username}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
