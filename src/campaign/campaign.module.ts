import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Campaign } from './entities/campaign.entity';
import { CampaignMetrics } from './entities/metrics.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Campaign, CampaignMetrics])],
  exports: [TypeOrmModule],
})
export class CampaignModule {}
