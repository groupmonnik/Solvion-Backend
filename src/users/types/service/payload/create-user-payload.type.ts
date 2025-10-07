import { UserRole } from '@/users/entities/user.entity';

export type CreateUserPayload = {
  name: string;
  email: string;
  passwordHash: string;
  role?: UserRole;
  business?: string;
};
