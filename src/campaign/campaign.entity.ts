import { Creative } from '@/creative/entities/creative.entity';
import { GoogleCampaignDetails } from '@/googleProvider/entities/googleCampaingDetail';
import { MetaCampaignDetail } from '@/metaProvider/entities/metaCampaingDetail';
import { Column, Entity, OneToMany, OneToOne, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Campaign {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  status: string;

  @Column()
  objective: string;

  @Column()
  provider: 'Meta' | 'Google';

  @OneToMany(() => Creative, creative => creative.campaign)
  creatives: Creative[];

  @OneToOne(() => GoogleCampaignDetails, googleDetail => googleDetail.campaign)
  googleDetail?: GoogleCampaignDetails;

  @OneToOne(() => MetaCampaignDetail, metaDetail => metaDetail.campaign)
  metaDetail?: MetaCampaignDetail;
}
