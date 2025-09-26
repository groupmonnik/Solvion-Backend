import { Campaign } from '@/campaign/campaign.entity';
import {
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
} from 'typeorm';

export class Creative {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: true })
  adGroupId: string;

  @Column()
  name: string;

  @Column()
  headline: string;

  @Column()
  description: string;

  @Column()
  finalUrl: string;

  @Column({ nullable: true })
  imageUrl?: string;

  @Column({ nullable: true })
  videoUrl?: string;

  @Column()
  callToAction: string;

  @Column()
  status: 'active' | 'paused' | 'removed' | 'archived';

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => Campaign, campaign => campaign.creatives)
  campaign: Campaign;
}
