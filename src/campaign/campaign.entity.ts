import { AdAccount } from '@/adAccount/entities/adAccount.entity';
import { Creative } from '@/creative/entities/creative.entity';
import { CampaignMetrics } from '@/metrics/entitites/campaingMetrics.entity';
import { Column, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum CampaignStatus {
  ACTIVE = 'active',
  PAUSED = 'paused',
  DELETED = 'deleted',
  ARCHIVED = 'archived',
}

@Entity()
export class Campaign {
  @ApiProperty({
    description: 'Campaign unique identifier',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    description: 'Associated ad account',
    type: () => AdAccount,
  })
  @ManyToOne(() => AdAccount, adAccount => adAccount.campaigns, {
    nullable: false,
    cascade: true,
    orphanedRowAction: 'delete',
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'account_id' })
  account: AdAccount;

  @ApiProperty({
    description: 'Campaign name',
    example: 'Summer Sale 2024',
    minLength: 1,
  })
  @Column()
  name: string;

  @ApiProperty({
    description: 'Campaign objective',
    example: 'CONVERSIONS',
  })
  @Column()
  objective: string;

  @ApiProperty({
    description: 'Campaign status',
    example: 'active',
    enum: CampaignStatus,
    default: CampaignStatus.PAUSED,
  })
  @Column({ type: 'enum', enum: CampaignStatus, default: CampaignStatus.PAUSED })
  status: CampaignStatus;

  @ApiPropertyOptional({
    description: 'Daily budget for the campaign',
    example: 100.0,
    type: Number,
  })
  @Column({ name: 'daily_budget', type: 'decimal', nullable: true })
  dailyBudget: number | null;

  @ApiPropertyOptional({
    description: 'Campaign start date',
    example: '2024-01-01',
    type: Date,
  })
  @Column({ name: 'start_date', type: 'date', nullable: true })
  startDate: Date | null;

  @ApiPropertyOptional({
    description: 'Campaign end date',
    example: '2024-12-31',
    type: Date,
  })
  @Column({ name: 'end_date', type: 'date', nullable: true })
  endDate: Date | null;

  @ApiProperty({
    description: 'Campaign creation timestamp',
    example: '2023-01-01T00:00:00.000Z',
  })
  @Column({ name: 'created_at', type: 'timestamp' })
  createdAt: Date;

  @ApiPropertyOptional({
    type: () => [CampaignMetrics],
    description: 'List of metrics associated with the campaign',
  })
  @OneToMany(() => CampaignMetrics, metrics => metrics.campaign, {
    cascade: ['insert', 'update'],
  })
  metrics: CampaignMetrics[];

  @ApiPropertyOptional({
    type: () => [Creative],
    description: 'List of creatives associated with the campaign',
  })
  @OneToMany(() => Creative, creative => creative.campaign, {
    cascade: ['insert', 'update'],
  })
  creatives: Creative[];
}
