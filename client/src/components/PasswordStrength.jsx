/** Simple client-side hint. The server enforces the real policy. */
export function scorePassword(p) {
  let score = 0;
  if (p.length >= 10) score++;
  if (p.length >= 14) score++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++;
  if (/\d/.test(p)) score++;
  if (/[^a-zA-Z0-9]/.test(p)) score++;
  return Math.min(score, 4);
}

const LABELS = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong'];

export default function PasswordStrength({ password }) {
  if (!password) return null;
  const score = scorePassword(password);
  return (
    <div className="strength" aria-live="polite">
      <div className="bars">
        {[0, 1, 2, 3].map((i) => (
          <span key={i} className={i < score ? `on s${score}` : ''} />
        ))}
      </div>
      <small>{LABELS[score]}</small>
    </div>
  );
}
