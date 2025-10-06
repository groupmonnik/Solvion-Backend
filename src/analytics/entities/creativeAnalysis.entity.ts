import { Creative } from '@/creative/entities/creative.entity';
import {
  Column,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
export class CreativeAnalysis {
  @ApiProperty({
    description: 'Creative analysis unique identifier',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    description: 'Associated creative',
    type: () => Creative,
  })
  @OneToOne(() => Creative, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'creative_id' })
  creative: Creative;

  @ApiProperty({
    description: 'Sentiment analysis of the text',
    example: 'positive',
  })
  @Column({ name: 'feeling_text' })
  feelingText: string;

  @ApiProperty({
    description: 'Predominant color in the creative',
    example: '#FF5733',
  })
  @Column({ name: 'predominant_color' })
  predominantColor: string;

  @ApiProperty({
    description: 'Video length in seconds',
    example: 30,
  })
  @Column({ name: 'video_length', type: 'int' })
  videoLength: number;

  @ApiProperty({
    description: 'Average engagement rate',
    example: 4.25,
  })
  @Column({ name: 'avg_engagement_rate', type: 'decimal', precision: 5, scale: 2 })
  avgEngagementRate: number;

  @ApiProperty({
    description: 'AI-generated recommendations for improvement',
    example: 'Consider using brighter colors and shorter text for better engagement',
  })
  @Column()
  recommendations: string;

  @ApiProperty({
    description: 'Overall quality score from AI analysis',
    example: 87.5,
  })
  @Column({ name: 'general_score', type: 'decimal', precision: 5, scale: 2 })
  generalScore: number;

  @ApiProperty({
    description: 'Last update timestamp',
    example: '2023-01-01T00:00:00.000Z',
  })
  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
