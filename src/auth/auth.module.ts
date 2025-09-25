import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '@/users/entities/user.entity';
import { EncryptService } from '../common/encrypt/encrypt.service.auth';
import { PassportModule } from '@nestjs/passport';
import { AccessTokenJwtStrategy } from './config/acces-token-jwt-strategy.auth';
import accessTokenJwtConfig from './config/access-token-jwt.config';

@Module({
  imports: [
    ConfigModule.forFeature(accessTokenJwtConfig),
    TypeOrmModule.forFeature([User]),
    PassportModule.register({ defaultStrategy: 'AccessTokenJwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('SECRET_KEY_JWT'),
        signOptions: { expiresIn: configService.get<string>('JWT_EXPIRES_IN') },
      }),
    }),
  ],
  providers: [AuthService, EncryptService, AccessTokenJwtStrategy],
  controllers: [AuthController],
  exports: [AuthService, EncryptService],
})
export class AuthModule {}
