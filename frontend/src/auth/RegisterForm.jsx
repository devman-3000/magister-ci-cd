import React from 'react'
export default function RegisterForm({ onSubmit }) {
  const [username, setUsername] = React.useState('')
  const [password, setPassword] = React.useState('')
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit(username, password) }}>
      <h3>Реєстрація</h3>
      <div style={{ display: 'grid', gap: 8 }}>
        <input placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit">Зареєструватися</button>
      </div>
    </form>
  )
}