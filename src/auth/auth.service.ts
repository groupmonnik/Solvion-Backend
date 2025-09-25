import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { LoginPayload } from './service/payload/login-auth-payload.type';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '@/users/entities/user.entity';
import { LoginDto } from './dto/login-auth.dto';
import { EncryptService } from '@/common/encrypt/encrypt.service.auth';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly encryptService: EncryptService,
  ) {}

  async generate(value: LoginPayload) {
    const { email, password } = value;
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      throw new HttpExceptionCustom(null, HttpStatus.NOT_FOUND, 'user not found');
    }

    if (user.password !== password) {
      throw new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST, 'password is incorrect');
    }

    const accessPayload = { sub: user.id, email: user.email };
    const rawAccessToken = this.jwtService.sign(accessPayload);

    const refreshPayload = { sub: user.id };
    const rawRefreshToken = this.jwtService.sign(refreshPayload, {
      expiresIn: '1d',
    });

    const accessToken = this.encryptService.encrypt(rawAccessToken);
    const refreshToken = this.encryptService.encrypt(rawRefreshToken);

    return { accessToken, refreshToken };
  }

  async refreshToken(refreshToken: string) {
    try {
      const decryptedRefresh = this.encryptService.decrypt(refreshToken);

      const user = await this.verify(decryptedRefresh);

      if (!user) {
        throw new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'invalid refresh token');
      }

      const value: LoginDto = {
        email: user.email,
        password: user.password,
      };

      return this.generate(value);
    } catch (error) {
      if (error instanceof HttpExceptionCustom) {
        throw error;
      }
      throw new HttpExceptionCustom({ error }, HttpStatus.UNAUTHORIZED, 'Invalid refresh token');
    }
  }

  async verify(token: string) {
    try {
      const decoded: { sub: number; [key: string]: any } = this.jwtService.verify(token);
      const user = await this.userRepository.findOne({ where: { id: decoded.sub } });
      if (!user) {
        throw new HttpExceptionCustom(null, HttpStatus.NOT_FOUND, 'User not found');
      }
      return user;
    } catch (error) {
      if (error instanceof HttpExceptionCustom) {
        throw error;
      }
      throw new HttpExceptionCustom(
        { error },
        HttpStatus.INTERNAL_SERVER_ERROR,
        'Internal Server Error',
      );
    }
  }
}
