import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/guards/access-token-jwt.guard';
import { AdsAccountModule } from './ads-account/ads.account.module';
import { CampaignModule } from './campaign/campaign.module';
import { CreativeModule } from './creative/creative.module';
import { AnalyticsModule } from './analytics/analytics.module';
import { GoogleAccountsModule } from './integrations/google/google.accounts.module';
import { UsersModule } from './users/users.module';
import { PredictionModule } from './prediction/prediction.module';
import { MetaAccountsModule } from './integrations/meta/meta.accounts.module';

@Module({
  imports: [
    UsersModule,
    AdsAccountModule,
    CampaignModule,
    CreativeModule,
    AnalyticsModule,
    AuthModule,
    GoogleAccountsModule,
    MetaAccountsModule,
    PredictionModule,
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
  ],
  providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
})
export class AppModule {}
