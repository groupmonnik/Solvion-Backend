import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity()
export class GoogleAccount {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  userId: number;

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
}
