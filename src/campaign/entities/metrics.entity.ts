import { Campaign } from '@/campaign/entities/campaign.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity('campaign_metrics')
export class CampaignMetrics {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Campaign, {
    nullable: false,
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'campaign_id' })
  campaign: Campaign;

  @Column({ type: 'date' })
  date: Date;

  @Column({ type: 'int', default: 0 })
  impressions: number;

  @Column({ type: 'int', default: 0 })
  clicks: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  crt: number;

  @Column({ name: 'average_cpc', type: 'decimal', precision: 10, scale: 2, default: 0 })
  averageCpc: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  cpm: number;

  @Column({ type: 'int', default: 0 })
  conversions: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  conversionCost: number;

  @Column({ type: 'decimal', precision: 12, scale: 2, default: 0 })
  revenue: number;

  @Column({ type: 'decimal', precision: 10, scale: 2 })
  roas: number;

  @Column({ name: 'total_cost', type: 'decimal', precision: 12, scale: 2, default: 0 })
  totalCost: number;

  @Column({ type: 'int', default: 0 })
  reached: number;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
