import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/guards/access-token-jwt.guard';

import { AdAccountModule } from './adAccount/adAccount.module';
import { CampaignModule } from './campaign/campaign.module';
import { CreativeModule } from './creative/creative.module';
import { MetricsModule } from './metrics/metrics.module';
import { AnalyticsModule } from './analytics/analytics.module';
import { GoogleAccountsModule } from './google-accounts/google-accounts.module';
import { User } from './users/entities/user.entity';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    UsersModule,
    AdAccountModule,
    CampaignModule,
    CreativeModule,
    MetricsModule,
    AnalyticsModule,
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
        synchronize: configService.get<string>('NODE_ENV', 'development') === 'development',
        autoLoadEntities: true,
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    GoogleAccountsModule,
  ],
  providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
})
export class AppModule {}
