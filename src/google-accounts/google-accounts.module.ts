import { Module } from '@nestjs/common';
import { GoogleAccountsController } from './google-accounts.controller';
import { GoogleAccountsService } from './google-accounts.service';

@Module({
  controllers: [GoogleAccountsController],
  providers: [GoogleAccountsService],
})
export class GoogleAccountsModule {}
