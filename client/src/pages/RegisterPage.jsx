import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext.jsx';
import PasswordStrength from '../components/PasswordStrength.jsx';

export default function RegisterPage() {
  const { register } = useAuth();
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const update = (field) => (e) => setForm({ ...form, [field]: e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    if (form.password !== form.confirm) return setError('Passwords do not match');
    setBusy(true);
    setError('');
    try {
      await register({ name: form.name, email: form.email, password: form.password });
    } catch (err) {
      setError(err.body?.error === 'email_in_use' ? 'That email is already registered' : err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="auth-card">
      <h1>Create account</h1>
      <form onSubmit={submit} noValidate>
        <label>
          Name
          <input autoComplete="name" value={form.name} onChange={update('name')} required />
        </label>
        <label>
          Email
          <input type="email" autoComplete="email" value={form.email} onChange={update('email')} required />
        </label>
        <label>
          Password
          <input type="password" autoComplete="new-password" value={form.password} onChange={update('password')} required />
        </label>
        <PasswordStrength password={form.password} />
        <small className="muted">At least 10 characters, with letters and numbers.</small>
        <label>
          Confirm password
          <input type="password" autoComplete="new-password" value={form.confirm} onChange={update('confirm')} required />
        </label>
        {error && <p className="error" role="alert">{error}</p>}
        <button disabled={busy}>{busy ? 'Creating…' : 'Create account'}</button>
      </form>
      <p className="muted">
        Already registered? <Link to="/login">Sign in</Link>
      </p>
    </main>
  );
}
