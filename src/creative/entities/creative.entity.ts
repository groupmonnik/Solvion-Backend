import { CreativeAnalysis } from '@/analytics/entities/analysis.entity';
import { Campaign } from '@/campaign/entities/campaign.entity';
import { CreativeMetrics } from '@/creative/entities/metrics.entity';
import { CreativeType } from '../enum/creative.type.enum';
import {
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Entity,
  ManyToOne,
  JoinColumn,
  OneToOne,
  OneToMany,
} from 'typeorm';

@Entity('creative')
export class Creative {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Campaign, campaign => campaign.creatives, {
    nullable: false,
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'campaign_id' })
  campaign: Campaign;

  @Column()
  name: string;

  @Column({ type: 'enum', enum: CreativeType })
  type: CreativeType;

  @Column({ name: 'media_url' })
  mediaUrl: string;

  @Column({ name: 'main_text', type: 'text' })
  mainText: string;

  @Column()
  title: string;

  @Column()
  description: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @OneToMany(() => CreativeMetrics, metrics => metrics.creative, {
    cascade: ['insert', 'update'],
  })
  metrics: CreativeMetrics[];

  @OneToOne(() => CreativeAnalysis, analysis => analysis.creative, {
    cascade: ['insert', 'update'],
  })
  analysis: CreativeAnalysis;
}
