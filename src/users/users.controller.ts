import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { CreateUserReturn } from './types/service/return/create-user-return.type';
import { FindAllUsersReturn } from './types/service/return/find-all-users-return.type';
import { FindUserByIdReturn } from './types/service/return/find-user-by-id-return.type';
import { UpdateUserReturn } from './types/service/return/update-user-return.type';
import { RemoveUserReturn } from './types/service/return/remove-user-return.type';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async create(createUserDto: CreateUserDto): Promise<CreateUserReturn> {
    return this.usersService.createUser(createUserDto);
  }

  @Get()
  findAll(): Promise<FindAllUsersReturn> {
    return this.usersService.findAllUsers();
  }

  @Get(':id')
  findOne(@Param('id') id: string): Promise<FindUserByIdReturn> {
    return this.usersService.findUserById({ id: +id });
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto): Promise<UpdateUserReturn> {
    return this.usersService.updateUser({ id: +id, ...updateUserDto });
  }

  @Delete(':id')
  remove(@Param('id') id: string): Promise<RemoveUserReturn> {
    return this.usersService.removeUser({ id: +id });
  }
}
