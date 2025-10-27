import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AdsAccount } from './entities/ads.account.entity';

@Module({
  imports: [TypeOrmModule.forFeature([AdsAccount])],
  exports: [TypeOrmModule],
})
export class AdsAccountModule {}
