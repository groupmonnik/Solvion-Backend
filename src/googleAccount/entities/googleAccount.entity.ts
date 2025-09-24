import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn } from 'typeorm';
import { User } from '../../users/entities/user.entity';

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

  @ManyToOne(() => User, { nullable: false, onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;
}
