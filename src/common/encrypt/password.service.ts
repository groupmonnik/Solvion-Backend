import { compare, hash } from 'bcrypt';

export class PasswordService {
  static readonly saltOrRounds = Number(process.env.BCRYPT_ROUNDS) || 10;

  static hashPassword(password: string): Promise<string> {
    return hash(password, this.saltOrRounds);
  }

  static verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    return compare(password, hashedPassword);
  }
}
