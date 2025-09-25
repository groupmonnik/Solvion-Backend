import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class EncryptService {
  private readonly ALGORITHM = 'aes-256-cbc';
  private readonly key = Buffer.from(process.env.CRYPTO_KEY!, 'hex'); // 32 bytes

  encrypt(text: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.ALGORITHM, this.key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return `${encrypted}:${iv.toString('hex')}`;
  }

  decrypt(encrypted: string): string {
    const [encryptedText, ivHex] = encrypted.split(':');
    const iv = Buffer.from(ivHex, 'hex');

    const decipher = crypto.createDecipheriv(this.ALGORITHM, this.key, iv);

    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
