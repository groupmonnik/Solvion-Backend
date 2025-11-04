import {
  Column,
  CreateDateColumn,
  Entity,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Campaign } from '@/campaign/entities/campaign.entity';

@Entity('predictions')
export class Prediction {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Campaign, (campaign) => campaign.predictions, {
    nullable: false,
    onDelete: 'CASCADE',
  })
  campaign: Campaign;

  @Column({ name: 'predicted_period', type: 'date' })
  predictedPeriod: Date;

  @Column({ name: 'predicted_investment', type: 'decimal', precision: 12, scale: 2 })
  predictedInvestment: number;

  @Column({ name: 'predicted_conversions', type: 'int' })
  predictedConversions: number;

  @Column({ name: 'predicted_roas', type: 'decimal', precision: 10, scale: 2 })
  predictedRoas: number;

  @Column({ name: 'confidence', type: 'decimal', precision: 5, scale: 2 })
  confidence: number;

  @Column({ name: 'model_used' })
  modelUsed: string;

  @CreateDateColumn({ name: 'generated_at' })
  generatedAt: Date;
}
