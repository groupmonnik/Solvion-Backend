import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Creative } from './entities/creative.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Creative])],
  exports: [TypeOrmModule],
})
export class CreativeModule {}
