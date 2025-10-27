import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { User } from '@/users/entities/user.entity';
import { AdsAccount } from '@/ads-account/entities/ads.account.entity';
import { CreativeAnalysis } from '@/analytics/entities/analysis.entity';
import { Creative } from '@/creative/entities/creative.entity';
import { CampaignMetrics } from '@/campaign/entities/metrics.entity';
import { CreativeMetrics } from '@/creative/entities/metrics.entity';
import { Campaign } from '@/campaign/entities/campaign.entity';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres' as const,
        host: configService.get<string>('TEST_DB_HOST', 'localhost'),
        port: configService.get<number>('TEST_DB_PORT', 5432),
        username: configService.get<string>('TEST_DB_USERNAME', 'postgres'),
        password: configService.get<string>('TEST_DB_PASSWORD', 'postgres'),
        database: configService.get<string>('TEST_DB_DATABASE', 'solvion_test'),
        entities: [
          User,
          AdsAccount,
          CreativeAnalysis,
          Campaign,
          Creative,
          CampaignMetrics,
          CreativeMetrics,
        ],
        //autoLoadEntities: true,
        synchronize: true,
        dropSchema: true, // Limpa o schema antes de cada execução de teste
      }),
      inject: [ConfigService],
    }),
  ],
  exports: [TypeOrmModule],
})
export class TestDatabaseModule {}
