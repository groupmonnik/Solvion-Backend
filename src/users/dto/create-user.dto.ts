import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({
    description: 'User first name',
    example: 'John',
    minLength: 1,
  })
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({
    description: 'User last name',
    example: 'Doe',
    minLength: 1,
  })
  @IsNotEmpty()
  lastName: string;

  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
    format: 'email',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'mySecurePassword123',
    minLength: 8,
  })
  @IsNotEmpty()
  password: string;
}
