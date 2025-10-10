import { IsEmail, IsString, IsStrongPassword } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    example: 'sherekgostoso3@gmail.com',
    description: 'User email address',
  })
  @IsEmail()
  @IsString()
  email: string;

  @ApiProperty({
    example: 'Tos200689!',
    description:
      'User password. Must contain at least 8 characters, including uppercase, lowercase, number, and symbol.',
    minLength: 8,
  })
  @IsString()
  @IsStrongPassword({
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  })
  password: string;
}
