import { UserRole } from '@/users/entities/user.entity';

export type UpdateUserPayload = {
  name?: string;
  email?: string;
  password?: string;
  role?: UserRole;
  business?: string;
};
