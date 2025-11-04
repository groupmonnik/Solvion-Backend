import { GoogleExceptionFilter } from '@/common/exception-filters/google-exception/google.exception.filter';
import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { GoogleAccountsController } from './google.accounts.controller';
import { GoogleAccountsService } from './google.accounts.service';

@Module({
  controllers: [GoogleAccountsController],
  providers: [GoogleAccountsService, { provide: APP_FILTER, useClass: GoogleExceptionFilter }],
})
export class GoogleAccountsModule {}
