import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { Campaign } from '@/campaign/campaign.entity';

@Entity()
export class GoogleAccount {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  customerId: string;

  @Column()
  customerEmail: string;

  @Column({ type: 'simple-array', nullable: true })
  scopes?: string[];

  @Column()
  refreshToken: string;

  @Column({ type: 'timestamp', nullable: true })
  refreshTokenExpiresIn: number;

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
