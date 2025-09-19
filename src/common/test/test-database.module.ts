import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../../users/entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      useFactory: () => {
        return {
          type: 'sqlite',
          database: ':memory:',
          entities: [User],
          synchronize: true,
        };
      },
    }),
  ],
  exports: [TypeOrmModule],
})
export class TestDatabaseModule {}
