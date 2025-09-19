import { HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { InferIdType } from '@/common/types/object-with-id.type';
import { CreateUserPayload } from './types/service/payload/create-user-payload.type';
import { UpdateUserPayload } from './types/service/payload/update-user-payload.type';
import { FindUserByIdPayload } from './types/service/payload/find-user-by-id-payload.type';
import { RemoveUserPayload } from './types/service/payload/remove-user-payload.type';
import { CreateUserReturn } from './types/service/return/create-user-return.type';
import { FindAllUsersReturn } from './types/service/return/find-all-users-return.type';
import { FindUserByIdReturn } from './types/service/return/find-user-by-id-return.type';
import { UpdateUserReturn } from './types/service/return/update-user-return.type';
import { RemoveUserReturn } from './types/service/return/remove-user-return.type';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  async createUser(payload: CreateUserPayload): Promise<CreateUserReturn> {
    const createUserResult = this.usersRepository.create(payload);
    return await this.usersRepository.save(createUserResult);
  }

  async findAllUsers(): Promise<FindAllUsersReturn> {
    return await this.usersRepository.find();
  }

  async findUserById(payload: FindUserByIdPayload): Promise<FindUserByIdReturn> {
    return await this.usersRepository.findOneBy({ id: payload.id });
  }

  async updateUser(payload: UpdateUserPayload & { id: number }): Promise<UpdateUserReturn> {
    const { id, ...updateData } = payload;
    await this.usersRepository.update(id, updateData);
    const findUserByIdResult = await this.findUserById({ id });

    if (!findUserByIdResult) {
      throw new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST);
    }

    return findUserByIdResult as InferIdType<User, number>;
  }

  async removeUser(payload: RemoveUserPayload): Promise<RemoveUserReturn> {
    await this.usersRepository.delete(payload.id);
  }
}
