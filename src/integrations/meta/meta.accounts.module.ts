import { Module } from "@nestjs/common";
import { MetaAuthService } from "./meta.accounts.service";
import { MetaAuthController } from "./meta.accounts.controller";

@Module({
  imports: [],
  controllers: [MetaAuthController],
  providers: [MetaAuthService],
})
export class MetaAccountsModule {}
