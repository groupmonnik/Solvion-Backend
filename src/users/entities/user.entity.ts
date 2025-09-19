import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
export class User {
  @ApiProperty({
    description: 'User unique identifier',
    example: 1,
  })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({
    description: 'User first name',
    example: 'John',
    minLength: 1,
  })
  @Column()
  firstName: string;

  @ApiProperty({
    description: 'User last name',
    example: 'Doe',
    minLength: 1,
  })
  @Column()
  lastName: string;

  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
    format: 'email',
  })
  @Column()
  email: string;

  @ApiProperty({
    description: 'User password (hashed)',
    example: 'hashedPassword123',
    minLength: 8,
  })
  @Column()
  password: string;
}
