import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '@/users/entities/user.entity';
import { EncryptService } from '../common/encrypt/encrypt.service.auth';
import { PassportModule } from '@nestjs/passport';
import { AccessTokenJwtStrategy } from './strategies/access-token-jwt-strategy.auth';
import accessTokenJwtConfig from './config/access-token-jwt.config';
import refreshTokenJwtConfig from './config/refresh-token-jwt.config';

@Module({
  imports: [
    ConfigModule.forFeature(accessTokenJwtConfig),
    ConfigModule.forFeature(refreshTokenJwtConfig),
    TypeOrmModule.forFeature([User]),
    PassportModule.register({ defaultStrategy: 'AccessTokenJwt' }),
    JwtModule.registerAsync({ useFactory: () => ({}) }),
  ],
  providers: [AuthService, EncryptService, AccessTokenJwtStrategy],
  controllers: [AuthController],
  exports: [AuthService, EncryptService],
})
export class AuthModule {}
