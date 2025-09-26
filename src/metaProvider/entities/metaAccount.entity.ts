import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  OneToMany,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { Campaign } from '@/campaign/campaign.entity';

@Entity()
export class MetaAccount {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  facebookUserId: string;

  @Column()
  accessToken: string;

  @Column({ type: 'timestamp' })
  expiresAt: number;

  @Column({ name: 'page_access_tokens', type: 'json', nullable: true })
  pageAccessTokens?: Array<{
    pageId: string;
    pageName: string;
    accessToken: string;
    category: string;
    expiresAt?: Date;
  }>;

  @Column({ type: 'json', nullable: true })
  adAccounts?: Array<{
    adAccountId: string;
    name: string;
    currency: string;
    status: string;
  }>;

  @Column({ type: 'simple-array', nullable: true })
  scopes?: string[];

  @Column({ default: 'active' })
  status: 'active' | 'inactive' | 'expired';

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => Campaign, campaign => campaign.accountId)
  campaigns: Campaign[];

  @ManyToOne(() => User, { nullable: false, onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;
}
