import { Controller, Get, Post, Body, Patch, Param, Delete, Res, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import type { FastifyReply } from 'fastify';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { CreateUserResponse } from './types/controller/response/create-user-response.type';
import { FindAllUsersResponse } from './types/controller/response/find-all-users-response.type';
import { FindUserByIdResponse } from './types/controller/response/find-user-by-id-response.type';
import { UpdateUserResponse } from './types/controller/response/update-user-response.type';
import { RemoveUserResponse } from './types/controller/response/remove-user-response.type';

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new user' })
  @ApiResponse({
    status: 201,
    description: 'User created successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - validation error',
  })
  async create(
    @Body() createUserDto: CreateUserDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<CreateUserResponse> {
    const createUserResult = await this.usersService.createUser(createUserDto);

    reply.status(HttpStatus.CREATED);

    return {
      statusCode: HttpStatus.CREATED,
      message: 'User created successfully',
      success: true,
      data: createUserResult,
    };
  }

  @Get()
  @ApiOperation({ summary: 'Get all users' })
  @ApiResponse({
    status: 200,
    description: 'Users retrieved successfully',
  })
  async findAll(@Res({ passthrough: true }) reply: FastifyReply): Promise<FindAllUsersResponse> {
    const findAllUsersResult = await this.usersService.findAllUsers();

    reply.status(HttpStatus.OK);

    return {
      statusCode: HttpStatus.OK,
      message: 'Users retrieved successfully',
      success: true,
      data: findAllUsersResult,
    };
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get user by ID' })
  @ApiResponse({
    status: 200,
    description: 'User retrieved successfully',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  async findOne(
    @Param('id') id: string,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<FindUserByIdResponse> {
    const findUserByIdResult = await this.usersService.findUserById({ id: +id });

    reply.status(HttpStatus.OK);

    return {
      statusCode: HttpStatus.OK,
      message: 'User retrieved successfully',
      success: true,
      data: findUserByIdResult,
    };
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update user by ID' })
  @ApiResponse({
    status: 200,
    description: 'User updated successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - validation error',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  async update(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<UpdateUserResponse> {
    const updateUserResult = await this.usersService.updateUser({ id: +id, ...updateUserDto });

    reply.status(HttpStatus.OK);

    return {
      statusCode: HttpStatus.OK,
      message: 'User updated successfully',
      success: true,
      data: updateUserResult,
    };
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete user by ID' })
  @ApiResponse({
    status: 200,
    description: 'User removed successfully',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  async remove(
    @Param('id') id: string,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<RemoveUserResponse> {
    const removeUserResult = await this.usersService.removeUser({ id: +id });

    reply.status(HttpStatus.OK);

    return {
      statusCode: HttpStatus.OK,
      message: 'User removed successfully',
      success: true,
      data: removeUserResult,
    };
  }
}
