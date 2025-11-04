import { UserRole } from '@/users/enum/user.role.enum';

export type CreateUserPayload = {
  name: string;
  email: string;
  password: string;
  role?: UserRole;
  business?: string;
};
