import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AdAccount } from './entities/adAccount.entity';

@Module({
  imports: [TypeOrmModule.forFeature([AdAccount])],
  exports: [TypeOrmModule],
})
export class AdAccountModule {}
