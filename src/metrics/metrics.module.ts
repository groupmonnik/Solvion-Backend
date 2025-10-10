import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CampaignMetrics } from './entitites/campaingMetrics.entity';
import { CreativeMetrics } from './entitites/creativeMetrics.entity';

@Module({
  imports: [TypeOrmModule.forFeature([CampaignMetrics, CreativeMetrics])],
  exports: [TypeOrmModule],
})
export class MetricsModule {}
