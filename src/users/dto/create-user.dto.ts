import { IsEmail, IsNotEmpty, IsOptional, IsEnum } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { UserRole } from '@/users/enum/user.role.enum';

export class CreateUserDto {
  @ApiProperty({
    description: 'User full name',
    example: 'John Doe',
    minLength: 1,
  })
  @IsNotEmpty()
  name: string;

  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
    format: 'email',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'Tos200689!',
    description:
      'User password. Must contain at least 8 characters, including uppercase, lowercase, number, and symbol.',
    minLength: 8,
  })
  @IsNotEmpty()
  password: string;

  @ApiPropertyOptional({
    description: 'User role',
    example: 'client',
    enum: UserRole,
    default: UserRole.CLIENT,
  })
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;

  @ApiPropertyOptional({
    description: 'User business name',
    example: 'Tech Corp',
  })
  @IsOptional()
  business?: string;
}
