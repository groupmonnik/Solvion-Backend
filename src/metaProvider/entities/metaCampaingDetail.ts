import { Campaign } from '@/campaign/campaign.entity';
import { Column, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class MetaCampaignDetail {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  specialAdCategories: string;

  @Column('simple-json', { nullable: true })
  specialAdCategory: string[];

  @Column({ nullable: true })
  buyingType: string;

  @Column({ name: 'account_id', nullable: true })
  accountId: string;

  @Column({ nullable: true })
  name: string;

  @Column({ nullable: true })
  objective: string;

  @Column({ nullable: true })
  status: string;

  @Column({ nullable: true })
  effectiveStatus: string;

  @Column({ type: 'timestamp', nullable: true })
  createdTime: Date;

  @Column({ type: 'timestamp', nullable: true })
  updatedTime: Date;

  @Column({ type: 'timestamp', nullable: true })
  startTime: Date;

  @Column({ type: 'timestamp', nullable: true })
  stopTime: Date;

  @Column({ type: 'bigint', nullable: true })
  dailyBudget: string;

  @Column({ type: 'bigint', nullable: true })
  lifetimeBudget: string;

  @Column({ type: 'bigint', nullable: true })
  spendCap: string;

  @Column({ nullable: true })
  bidStrategy: string;

  @Column({ type: 'simple-json', nullable: true })
  promotedObject: Record<string, any>;

  @Column({ type: 'simple-array', nullable: true })
  pacingType: string[];

  @Column({ type: 'simple-array', nullable: true })
  adlabels: string[];

  @Column({ type: 'json', nullable: true })
  insights: Record<string, any>;

  @Column({ type: 'json', nullable: true })
  issuesInfo: Record<string, any>;

  @Column({ type: 'json', nullable: true })
  brandLiftStudies: Record<string, any>;

  @Column({ nullable: true })
  sourceCampaignId: string;

  @Column({ type: 'json', nullable: true })
  attributionSpec: Record<string, any>;

  @Column({ type: 'json', nullable: true })
  adsets: Record<string, any>;

  @OneToOne(() => Campaign, campaign => campaign.metaDetail, { onDelete: 'CASCADE' })
  @JoinColumn()
  campaign: Campaign;
}
