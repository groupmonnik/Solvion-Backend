import { Campaign } from '@/campaign/campaign.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
export class CampaignMetrics {
  @ApiProperty({
    description: 'Campaign metrics unique identifier',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    description: 'Associated campaign',
    type: () => Campaign,
  })
  @ManyToOne(() => Campaign, {
    nullable: false,
    cascade: true,
    orphanedRowAction: 'delete',
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'campaign_id' })
  campaign: Campaign;

  @ApiProperty({
    description: 'Metrics date',
    example: '2024-01-01',
    type: Date,
  })
  @Column({ type: 'date' })
  date: Date;

  @ApiProperty({
    description: 'Number of impressions',
    example: 10000,
    default: 0,
  })
  @Column({ type: 'int', default: 0 })
  impressions: number;

  @ApiProperty({
    description: 'Number of clicks',
    example: 250,
    default: 0,
  })
  @Column({ type: 'int', default: 0 })
  clicks: number;

  @ApiProperty({
    description: 'Click-through rate',
    example: 2.5,
    default: 0,
  })
  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  crt: number;

  @ApiProperty({
    description: 'Average cost per click',
    example: 1.25,
    default: 0,
  })
  @Column({ name: 'average_cpc', type: 'decimal', precision: 10, scale: 2, default: 0 })
  averageCpc: number;

  @ApiProperty({
    description: 'Cost per thousand impressions',
    example: 15.5,
    default: 0,
  })
  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  cpm: number;

  @ApiProperty({
    description: 'Number of conversions',
    example: 50,
    default: 0,
  })
  @Column({ type: 'int', default: 0 })
  conversions: number;

  @ApiProperty({
    description: 'Cost per conversion',
    example: 6.25,
    default: 0,
  })
  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  conversionCost: number;

  @ApiProperty({
    description: 'Revenue generated',
    example: 1500.0,
    default: 0,
  })
  @Column({ type: 'decimal', precision: 12, scale: 2, default: 0 })
  revenue: number;

  @ApiProperty({
    description: 'Return on ad spend',
    example: 4.8,
  })
  @Column({ type: 'decimal', precision: 10, scale: 2 })
  roas: number;

  @ApiProperty({
    description: 'Total cost of the campaign',
    example: 312.5,
    default: 0,
  })
  @Column({ name: 'total_cost', type: 'decimal', precision: 12, scale: 2, default: 0 })
  totalCost: number;

  @ApiProperty({
    description: 'Number of people reached',
    example: 8500,
    default: 0,
  })
  @Column({ type: 'int', default: 0 })
  reached: number;

  @ApiProperty({
    description: 'Metrics creation timestamp',
    example: '2023-01-01T00:00:00.000Z',
  })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
