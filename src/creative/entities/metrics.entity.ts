import { Creative } from '@/creative/entities/creative.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity('creative_metrics')
export class CreativeMetrics {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Creative, creative => creative.metrics, {
    nullable: false,
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'creative_id' })
  creative: Creative;

  @Column({ type: 'date' })
  date: Date;

  @Column({ type: 'int', default: 0 })
  impressions: number;

  @Column({ type: 'int', default: 0 })
  clicks: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  crt: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  engagement: number;

  @Column({ type: 'int', default: 0 })
  conversion: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  cost: number;

  @Column({ name: 'ia_performance', type: 'decimal', precision: 10, scale: 2, default: 0 })
  iaPerformance: number;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
