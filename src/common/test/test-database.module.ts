import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres' as const,
        host: configService.get<string>('TEST_DB_HOST', 'localhost'),
        port: configService.get<number>('TEST_DB_PORT', 5432),
        username: configService.get<string>('TEST_DB_USERNAME', 'postgres'),
        password: configService.get<string>('TEST_DB_PASSWORD', 'postgres'),
        database: configService.get<string>('TEST_DB_DATABASE', 'solvion_test'),
        autoLoadEntities: true,
        synchronize: true,
        dropSchema: true, // Limpa o schema antes de cada execução de teste
      }),
      inject: [ConfigService],
    }),
  ],
  exports: [TypeOrmModule],
})
export class TestDatabaseModule {}
