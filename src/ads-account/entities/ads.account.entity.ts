import { Campaign } from "@/campaign/entities/campaign.entity";
import { User } from "@/users/entities/user.entity";
import { Provider } from "../enum/provider.enum";
import { AccountStatus } from "../enum/account.status.enum";
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from "typeorm";

@Entity("ads_accounts")
export class AdsAccount {
  @PrimaryGeneratedColumn("uuid")
  id: string;

  @ManyToOne(() => User, (user) => user.adAccounts, {
    nullable: false,
    onDelete: "CASCADE",
  })
  @JoinColumn({ name: "user_id" })
  user: User;

  @Column({ type: "enum", enum: Provider, default: Provider.GOOGLE })
  provider: Provider;

  @Column({ name: "provider_name" })
  providerName: string;

  @Column()
  providerAccountId: string;

  @Column({ type: "enum", enum: AccountStatus, default: AccountStatus.PENDING })
  status: AccountStatus;

  @Column({ name: "hashed_token" })
  hashedToken: string;

  @CreateDateColumn({ name: "created_at" })
  createdAt: Date;

  @OneToMany(() => Campaign, (campaign) => campaign.account, {
    cascade: ["insert", "update"],
  })
  campaigns: Campaign[];
}
