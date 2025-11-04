import { AdsAccount } from '@/ads-account/entities/ads.account.entity';
import { Creative } from '@/creative/entities/creative.entity';
import { CampaignMetrics } from '@/campaign/entities/metrics.entity';
import { Column, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { CampaignStatus } from '../enum/campaign.status.enum';
import { Prediction } from '@/prediction/entities/prediction.entities';

@Entity('campaign')
export class Campaign {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => AdsAccount, adsAccount => adsAccount.campaigns, {
    nullable: false,
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'account_id' })
  account: AdsAccount;

  @Column()
  name: string;

  @Column()
  objective: string;

  @Column({ type: 'enum', enum: CampaignStatus, default: CampaignStatus.PAUSED })
  status: CampaignStatus;

  @Column({ name: 'daily_budget', type: 'decimal', nullable: true })
  dailyBudget: number | null;

  @Column({ name: 'start_date', type: 'date', nullable: true })
  startDate: Date | null;

  @Column({ name: 'end_date', type: 'date', nullable: true })
  endDate: Date | null;

  @Column({ name: 'created_at', type: 'timestamp' })
  createdAt: Date;

  @OneToMany(() => CampaignMetrics, metrics => metrics.campaign, {
    cascade: ['insert', 'update'],
  })
  metrics: CampaignMetrics[];

  @OneToMany(() => Creative, creative => creative.campaign, {
    cascade: ['insert', 'update'],
  })
  creatives: Creative[];

  @OneToMany(() => Prediction, (prediction) => prediction.campaign, {
    cascade: ['insert', 'update'],
  })
  predictions: Prediction[];
}
