import { Campaign } from '@/campaign/campaign.entity';
import { User } from '@/users/entities/user.entity';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';

export enum Provider {
  GOOGLE = 'google',
  FACEBOOK = 'facebook',
}

export enum AccountStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  PENDING = 'pending',
  SUSPENDED = 'suspended',
}

@Entity()
export class AdAccount {
  @ApiProperty({
    description: 'Ad account unique identifier',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    description: 'Associated user',
    type: () => User,
  })
  @ManyToOne(() => User, User => User.adAccounts, { nullable: false, onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ApiProperty({
    description: 'Provider of the ad account',
    example: 'google',
    enum: Provider,
    default: Provider.GOOGLE,
  })
  @Column({ type: 'enum', enum: Provider, default: Provider.GOOGLE })
  provider: Provider;

  @ApiProperty({
    description: 'Name of the provider',
    example: 'Google Ads',
  })
  @Column({ name: 'provider_name' })
  providerName: string;

  @ApiProperty({
    description: 'Account ID provided by the ad platform',
    example: '123-456-7890',
  })
  @Column()
  providerAccountId: string;

  @ApiProperty({
    description: 'Status of the ad account',
    example: 'active',
    enum: AccountStatus,
    default: AccountStatus.PENDING,
  })
  @Column({ type: 'enum', enum: AccountStatus, default: AccountStatus.PENDING })
  status: AccountStatus;

  @ApiProperty({
    description: 'Hashed authentication token for the ad platform',
    example: 'hashed_token_value',
  })
  @Column({ name: 'hashed_token' })
  hashedToken: string;

  @ApiProperty({
    description: 'Ad account creation timestamp',
    example: '2023-01-01T00:00:00.000Z',
  })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ApiPropertyOptional({
    type: () => [Campaign],
    description: 'List of campaigns associated with the ad account',
  })
  @OneToMany(() => Campaign, campaign => campaign.account)
  campaigns: Campaign[];
}
