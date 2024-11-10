// user.dto.ts
import {Database} from "bun:sqlite"
const db = new Database("database.db")

db.exec(
  "CREATE TABLE IF NOT EXISTS users (id integer primary key, email text not null, password_hash text not null)"
);

export const userDTO = {
  findUserByEmail: (email: string): User => {
    const stmt = db.query('SELECT * FROM users where email = ?')
    const user = stmt.get(email)
    console.log(user)
    return user as User;
  },
  createUser: async (user: UserWithoutId) => {
    const stmt = db.prepare('INSERT INTO users(email, password_hash) VALUES (?, ?)')
    const result = stmt.run(user.email, await Bun.password.hash(user.password));
    return {
      id: result.lastInsertRowid.toString()
    };
  },
  verifyPassword: async (password: string, hash: string) => {
    return await Bun.password.verify(password, hash);
  },
};

type User = {
  id: number;
  email: string;
  password_hash: string;
};

type UserWithoutId = Omit<User, "id"> & {
  password: string;
};
