import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CreativeAnalysis } from './entities/analysis.entity';

@Module({
  imports: [TypeOrmModule.forFeature([CreativeAnalysis])],
  exports: [TypeOrmModule],
})
export class AnalyticsModule {}
