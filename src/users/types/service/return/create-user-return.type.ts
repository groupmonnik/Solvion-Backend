import { User } from '@/users/entities/user.entity';
import { InferIdType } from '@/common/types/object-with-id.type';

export type CreateUserReturn = InferIdType<User, number>;
