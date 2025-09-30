import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './users/entities/user.entity';
import { AuthModule } from './auth/auth.module';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './auth/guards/access-token-jwt.guard';
import { GoogleAccountsService } from './google-accounts/google-accounts.service';
import { GoogleAccountsController } from './google-accounts/google-accounts.controller';
import { GoogleAccountsModule } from './google-accounts/google-accounts.module';

@Module({
  imports: [
    UsersModule,
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres' as const,
        host: configService.get<string>('DB_HOST'),
        port: configService.get<number>('DB_PORT'),
        username: configService.get<string>('DB_USERNAME'),
        password: configService.get<string>('DB_PASSWORD'),
        database: configService.get<string>('DB_DATABASE'),
        entities: [User],
        synchronize: configService.get<string>('NODE_ENV', 'development') === 'development',
        autoLoadEntities: true,
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    GoogleAccountsModule,
  ],
  providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }, GoogleAccountsService],
  controllers: [GoogleAccountsController],
})
export class AppModule {}
