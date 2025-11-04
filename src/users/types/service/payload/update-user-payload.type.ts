import { UserRole } from '@/users/enum/user.role.enum';

export type UpdateUserPayload = {
  name?: string;
  email?: string;
  password?: string;
  role?: UserRole;
  business?: string;
};
