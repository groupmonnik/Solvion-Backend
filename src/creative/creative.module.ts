import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Creative } from './entities/creative.entity';
import { CreativeMetrics } from './entities/metrics.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Creative, CreativeMetrics])],
  exports: [TypeOrmModule],
})
export class CreativeModule {}
