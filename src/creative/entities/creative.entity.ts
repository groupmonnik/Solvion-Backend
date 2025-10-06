import { CreativeAnalysis } from '@/analytics/entities/creativeAnalysis.entity';
import { Campaign } from '@/campaign/campaign.entity';
import { CreativeMetrics } from '@/metrics/entitites/creativeMetrics.entity';
import {
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Entity,
  ManyToOne,
  JoinColumn,
  OneToOne,
} from 'typeorm';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum CreativeType {
  IMAGE = 'image',
  VIDEO = 'video',
  CAROUSEL = 'carousel',
  TEXT = 'text',
}

@Entity()
export class Creative {
  @ApiProperty({
    description: 'Creative unique identifier',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    description: 'Associated campaign',
    type: () => Campaign,
  })
  @ManyToOne(() => Campaign, campaign => campaign.creatives, {
    nullable: false,
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'campaign_id' })
  campaign: Campaign;

  @ApiProperty({
    description: 'Creative name',
    example: 'Product Launch Banner',
    minLength: 1,
  })
  @Column()
  name: string;

  @ApiProperty({
    description: 'Creative type',
    example: 'image',
    enum: CreativeType,
  })
  @Column({ type: 'enum', enum: CreativeType })
  type: CreativeType;

  @ApiProperty({
    description: 'URL of the media file',
    example: 'https://example.com/media/banner.jpg',
    format: 'url',
  })
  @Column({ name: 'media_url' })
  mediaUrl: string;

  @ApiProperty({
    description: 'Main text content of the creative',
    example: 'Discover our new collection! Limited time offer.',
  })
  @Column({ name: 'main_text', type: 'text' })
  mainText: string;

  @ApiProperty({
    description: 'Creative title',
    example: 'New Collection Launch',
    minLength: 1,
  })
  @Column()
  title: string;

  @ApiProperty({
    description: 'Creative description',
    example: 'Check out our latest products with amazing discounts',
    minLength: 1,
  })
  @Column()
  description: string;

  @ApiProperty({
    description: 'Creative creation timestamp',
    example: '2023-01-01T00:00:00.000Z',
  })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ApiPropertyOptional({
    type: () => CreativeMetrics,
    description: 'Metrics associated with the creative',
  })
  @OneToOne(() => CreativeMetrics, metrics => metrics.creative)
  metrics: CreativeMetrics;

  @ApiPropertyOptional({
    type: () => CreativeAnalysis,
    description: 'AI analysis associated with the creative',
  })
  @OneToOne(() => CreativeAnalysis, analysis => analysis.creative)
  analysis: CreativeAnalysis;
}
