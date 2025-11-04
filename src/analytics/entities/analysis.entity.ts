import { Creative } from '@/creative/entities/creative.entity';
import {
  Column,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('analysis')
export class CreativeAnalysis {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @OneToOne(() => Creative, {
    cascade: true,
    orphanedRowAction: 'delete',
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'creative_id' })
  creative: Creative;

  @Column({ name: 'feeling_text' })
  feelingText: string;

  @Column({ name: 'predominant_color' })
  predominantColor: string;

  @Column({ name: 'video_length', type: 'int' })
  videoLength: number;

  @Column({ name: 'avg_engagement_rate', type: 'decimal', precision: 5, scale: 2 })
  avgEngagementRate: number;

  @Column()
  recommendations: string;

  @Column({ name: 'general_score', type: 'decimal', precision: 5, scale: 2 })
  generalScore: number;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
