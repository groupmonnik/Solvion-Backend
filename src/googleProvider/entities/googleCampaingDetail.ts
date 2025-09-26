import { Campaign } from '@/campaign/campaign.entity';
import { Column, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class GoogleCampaignDetails {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  advertisingChannelType: string;

  @Column('float')
  optimizationScore: number;

  @Column({ nullable: true })
  name: string;

  @Column({ nullable: true })
  status: string;

  @Column({ nullable: true })
  servingStatus: string;

  @Column({ nullable: true })
  advertisingChannelSubType: string;

  @Column({ type: 'date', nullable: true })
  startDate: string;

  @Column({ type: 'date', nullable: true })
  endDate: string;

  @Column({ type: 'bigint', nullable: true })
  campaignBudget: string;

  @Column({ nullable: true })
  biddingStrategyType: string;

  @Column({ nullable: true })
  biddingStrategy: string;

  @Column({ type: 'simple-array', nullable: true })
  labels: string[];

  @Column({ nullable: true })
  paymentMode: string;

  @Column({ type: 'json', nullable: true })
  frequencyCaps: Record<string, any>;

  @Column({ nullable: true })
  trackingUrlTemplate: string;

  @Column({ nullable: true })
  finalUrlSuffix: string;

  @Column({ type: 'json', nullable: true })
  networkSettings: Record<string, any>;

  @Column({ type: 'json', nullable: true })
  selectiveOptimization: Record<string, any>;

  @Column({ type: 'json', nullable: true })
  shoppingSetting: Record<string, any>;

  @Column({ type: 'json', nullable: true })
  appCampaignSetting: Record<string, any>;

  @Column({ type: 'json', nullable: true })
  videoCampaignSettings: Record<string, any>;

  @Column({ nullable: true })
  campaignGroup: string;

  @Column({ nullable: true })
  resourceName: string;

  @Column({ type: 'json', nullable: true })
  metrics: Record<string, any>;

  @Column({ type: 'json', nullable: true })
  adGroup: Record<string, any>;

  @OneToOne(() => Campaign, campaign => campaign.googleDetail, { onDelete: 'CASCADE' })
  @JoinColumn()
  campaign: Campaign;
}
