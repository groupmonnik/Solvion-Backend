import {
  Column,
  CreateDateColumn,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { AdAccount } from '@/adAccount/entities/adAccount.entity';

export enum UserRole {
  ADMIN = 'admin',
  ANALYST = 'analyst',
  CLIENT = 'client',
}

@Entity()
export class User {
  @ApiProperty({
    description: 'User unique identifier',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    description: 'User Name',
    example: 'John Doe',
    minLength: 1,
  })
  @Column()
  name: string;

  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
    format: 'email',
  })
  @Column({ unique: true })
  email: string;

  @ApiProperty({
    description: 'User password (hashed)',
    example: 'hashedPassword123',
    minLength: 8,
  })
  @Column({ name: 'password_hash' })
  passwordHash: string;

  @ApiProperty({
    description: 'User role',
    example: 'admin',
    enum: UserRole,
    default: UserRole.CLIENT,
  })
  @Column({ type: 'enum', enum: UserRole, default: UserRole.CLIENT })
  role: UserRole;

  @ApiPropertyOptional({
    description: 'User business',
    example: 'Tech Corp',
  })
  @Column({ type: 'varchar', nullable: true })
  business: string | null;

  @ApiProperty({ example: '2023-01-01T00:00:00.000Z' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
  @ApiProperty({ example: '2023-01-01T00:00:00.000Z' })
  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @ApiPropertyOptional({
    type: () => [AdAccount],
    description: 'List of ad accounts associated with the user',
  })
  @OneToMany(() => AdAccount, adAccount => adAccount.user)
  adAccounts: AdAccount[];
}
