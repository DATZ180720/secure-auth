import { useEffect, useState } from 'react';
import { useAuth } from '../auth/AuthContext.jsx';
import { api } from '../auth/api.js';
import PasswordStrength from '../components/PasswordStrength.jsx';

export default function AccountPage() {
  const { user, logout, changePassword } = useAuth();
  const [sessions, setSessions] = useState([]);
  const [pw, setPw] = useState({ currentPassword: '', newPassword: '' });
  const [message, setMessage] = useState({ type: '', text: '' });

  const loadSessions = () => api.sessions().then((d) => setSessions(d.sessions)).catch(() => {});
  useEffect(() => {
    loadSessions();
  }, []);

  const submitPassword = async (e) => {
    e.preventDefault();
    try {
      await changePassword(pw);
      setPw({ currentPassword: '', newPassword: '' });
      setMessage({ type: 'ok', text: 'Password updated. Other devices were signed out.' });
      loadSessions();
    } catch (err) {
      setMessage({ type: 'error', text: err.body?.error === 'invalid_current_password' ? 'Current password is incorrect' : err.message });
    }
  };

  return (
    <main className="account">
      <header>
        <div>
          <h1>Hi, {user.name}</h1>
          <p className="muted">{user.email} · member since {new Date(user.createdAt).toLocaleDateString()}</p>
        </div>
        <button className="secondary" onClick={() => logout()}>Sign out</button>
      </header>

      <section className="panel">
        <h2>Active sessions</h2>
        <ul className="sessions">
          {sessions.map((s) => (
            <li key={s.id}>
              <span>{s.userAgent ?? 'Unknown device'}</span>
              <small className="muted">since {new Date(s.createdAt).toLocaleString()}</small>
            </li>
          ))}
        </ul>
        <button className="danger" onClick={() => logout(true)}>Sign out of all devices</button>
      </section>

      <section className="panel">
        <h2>Change password</h2>
        <form onSubmit={submitPassword}>
          <label>
            Current password
            <input type="password" autoComplete="current-password" value={pw.currentPassword} onChange={(e) => setPw({ ...pw, currentPassword: e.target.value })} required />
          </label>
          <label>
            New password
            <input type="password" autoComplete="new-password" value={pw.newPassword} onChange={(e) => setPw({ ...pw, newPassword: e.target.value })} required />
          </label>
          <PasswordStrength password={pw.newPassword} />
          {message.text && <p className={message.type === 'ok' ? 'success' : 'error'} role="status">{message.text}</p>}
          <button>Update password</button>
        </form>
      </section>
    </main>
  );
}
