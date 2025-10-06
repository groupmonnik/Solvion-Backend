import { Creative } from '@/creative/entities/creative.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
export class CreativeMetrics {
  @ApiProperty({
    description: 'Creative metrics unique identifier',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    description: 'Associated creative',
    type: () => Creative,
  })
  @OneToOne(() => Creative, creative => creative.metrics, {
    nullable: false,
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'creative_id' })
  creative: Creative;

  @ApiProperty({
    description: 'Metrics date',
    example: '2024-01-01',
    type: Date,
  })
  @Column({ type: 'date' })
  date: Date;

  @ApiProperty({
    description: 'Number of impressions',
    example: 5000,
    default: 0,
  })
  @Column({ type: 'int', default: 0 })
  impressions: number;

  @ApiProperty({
    description: 'Number of clicks',
    example: 125,
    default: 0,
  })
  @Column({ type: 'int', default: 0 })
  clicks: number;

  @ApiProperty({
    description: 'Click-through rate',
    example: 2.5,
    default: 0,
  })
  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  crt: number;

  @ApiProperty({
    description: 'Engagement rate',
    example: 3.75,
    default: 0,
  })
  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  engagement: number;

  @ApiProperty({
    description: 'Number of conversions',
    example: 25,
    default: 0,
  })
  @Column({ type: 'int', default: 0 })
  conversion: number;

  @ApiProperty({
    description: 'Total cost',
    example: 156.25,
    default: 0,
  })
  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  cost: number;

  @ApiProperty({
    description: 'AI performance score',
    example: 85.5,
    default: 0,
  })
  @Column({ name: 'ia_performance', type: 'decimal', precision: 10, scale: 2, default: 0 })
  iaPerformance: number;

  @ApiProperty({
    description: 'Metrics creation timestamp',
    example: '2023-01-01T00:00:00.000Z',
  })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
