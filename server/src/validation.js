import { z } from 'zod';

const email = z.string().trim().toLowerCase().pipe(z.email('Invalid email')).pipe(z.string().max(254));

// NIST SP 800-63B: favour length over composition rules, cap length to
// avoid hashing DoS, and reject the most common passwords.
const COMMON_PASSWORDS = new Set([
  'password', 'password1', '12345678', '123456789', '1234567890', 'qwerty123',
  'iloveyou', 'admin123', 'welcome1', 'letmein1', 'password123', 'contraseña',
]);

export const password = z
  .string()
  .min(10, 'Password must be at least 10 characters')
  .max(128, 'Password must be at most 128 characters')
  .refine((p) => !COMMON_PASSWORDS.has(p.toLowerCase()), 'This password is too common')
  .refine((p) => /[a-zA-Z]/.test(p) && /\d/.test(p), 'Password must contain letters and numbers');

export const registerSchema = z.object({
  email,
  name: z.string().trim().min(2, 'Name is too short').max(80),
  password,
});

export const loginSchema = z.object({
  email,
  password: z.string().min(1).max(128),
});

export const changePasswordSchema = z
  .object({ currentPassword: z.string().min(1).max(128), newPassword: password })
  .refine((d) => d.currentPassword !== d.newPassword, { message: 'New password must be different', path: ['newPassword'] });

/** Express middleware: validates req.body and replaces it with the parsed value. */
export const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body ?? {});
  if (!result.success) {
    return res.status(400).json({
      error: 'validation_error',
      details: result.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
    });
  }
  req.body = result.data;
  next();
};
