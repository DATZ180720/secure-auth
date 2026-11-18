import { hash, verify } from '@node-rs/argon2';

// Argon2id with OWASP-recommended parameters (19 MiB memory, 2 iterations).
const OPTIONS = { memoryCost: 19456, timeCost: 2, parallelism: 1 };

export const hashPassword = (password) => hash(password, OPTIONS);

export async function verifyPassword(passwordHash, password) {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false;
  }
}

// A real hash of a random value. When a login uses an unknown email we still
// verify against this, so the response time doesn't reveal whether the
// account exists (prevents user enumeration by timing).
let dummyHash;
export async function burnVerifyTime(password) {
  dummyHash ??= await hashPassword(crypto.randomUUID());
  await verifyPassword(dummyHash, password);
  return false;
}
