import { UserRole } from '@/users/entities/user.entity';

export type UpdateUserPayload = {
  name?: string;
  email?: string;
  passwordHash?: string;
  role?: UserRole;
  business?: string;
};
