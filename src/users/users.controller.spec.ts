import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

describe('UsersController', () => {
  let controller: UsersController;

  const mockUsersService = {
    createUser: jest.fn(),
    findAllUsers: jest.fn(),
    findUserById: jest.fn(),
    updateUser: jest.fn(),
    removeUser: jest.fn(),
  };

  const mockReply = {
    status: jest.fn().mockReturnThis(),
  } as unknown as FastifyReply;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    }).compile();

    controller = module.get<UsersController>(UsersController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should create a user', async () => {
    const createUserDto: CreateUserDto = {
      firstName: 'John',
      lastName: 'Doe',
      email: 'john@example.com',
      password: 'password123',
    };

    const mockUser = { id: 1, ...createUserDto };
    mockUsersService.createUser.mockResolvedValue(mockUser);

    const createUserResult = await controller.create(createUserDto, mockReply);

    expect(mockUsersService.createUser).toHaveBeenCalledWith(createUserDto);
    expect(mockReply.status).toHaveBeenCalledWith(HttpStatus.CREATED);
    expect(createUserResult).toEqual({
      statusCode: HttpStatus.CREATED,
      message: 'User created successfully',
      success: true,
      data: mockUser,
    });
  });

  it('should return all users', async () => {
    const mockUsers = [
      {
        id: 1,
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      },
      {
        id: 2,
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane@example.com',
        password: 'password456',
      },
    ];

    mockUsersService.findAllUsers.mockResolvedValue(mockUsers);

    const findAllUsersResult = await controller.findAll(mockReply);

    expect(mockUsersService.findAllUsers).toHaveBeenCalled();
    expect(mockReply.status).toHaveBeenCalledWith(HttpStatus.OK);
    expect(findAllUsersResult).toEqual({
      statusCode: HttpStatus.OK,
      message: 'Users retrieved successfully',
      success: true,
      data: mockUsers,
    });
  });

  it('should return a single user', async () => {
    const mockUser = {
      id: 1,
      firstName: 'John',
      lastName: 'Doe',
      email: 'john@example.com',
      password: 'password123',
    };

    mockUsersService.findUserById.mockResolvedValue(mockUser);

    const findOneUserResult = await controller.findOne('1', mockReply);

    expect(mockUsersService.findUserById).toHaveBeenCalledWith({ id: 1 });
    expect(mockReply.status).toHaveBeenCalledWith(HttpStatus.OK);
    expect(findOneUserResult).toEqual({
      statusCode: HttpStatus.OK,
      message: 'User retrieved successfully',
      success: true,
      data: mockUser,
    });
  });

  it('should update a user', async () => {
    const updateUserDto: UpdateUserDto = {
      firstName: 'John Updated',
      lastName: 'Doe',
      email: 'johnupdated@example.com',
    };

    const mockUser = {
      id: 1,
      firstName: 'John Updated',
      lastName: 'Doe',
      email: 'johnupdated@example.com',
      password: 'password123',
    };

    mockUsersService.updateUser.mockResolvedValue(mockUser);

    const updateUserResult = await controller.update('1', updateUserDto, mockReply);

    expect(mockUsersService.updateUser).toHaveBeenCalledWith({ id: 1, ...updateUserDto });
    expect(mockReply.status).toHaveBeenCalledWith(HttpStatus.OK);
    expect(updateUserResult).toEqual({
      statusCode: HttpStatus.OK,
      message: 'User updated successfully',
      success: true,
      data: mockUser,
    });
  });

  it('should remove a user', async () => {
    mockUsersService.removeUser.mockResolvedValue(undefined);

    const removeUserResult = await controller.remove('1', mockReply);

    expect(mockUsersService.removeUser).toHaveBeenCalledWith({ id: 1 });
    expect(mockReply.status).toHaveBeenCalledWith(HttpStatus.OK);
    expect(removeUserResult).toEqual({
      statusCode: HttpStatus.OK,
      message: 'User removed successfully',
      success: true,
      data: undefined,
    });
  });
});
