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
      name: 'John Doe',
      email: 'john@example.com',
      password: 'hashedPassword123',
    };

    const mockUser = { id: '550e8400-e29b-41d4-a716-446655440000', ...createUserDto };
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
        id: '550e8400-e29b-41d4-a716-446655440000',
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedPassword123',
      },
      {
        id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'Jane Smith',
        email: 'jane@example.com',
        passwordHash: 'hashedPassword456',
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
      id: '550e8400-e29b-41d4-a716-446655440000',
      name: 'John Doe',
      email: 'john@example.com',
      passwordHash: 'hashedPassword123',
    };

    mockUsersService.findUserById.mockResolvedValue(mockUser);

    const findOneUserResult = await controller.findOne(
      '550e8400-e29b-41d4-a716-446655440000',
      mockReply,
    );

    expect(mockUsersService.findUserById).toHaveBeenCalledWith({
      id: '550e8400-e29b-41d4-a716-446655440000',
    });
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
      name: 'John Doe Updated',
      email: 'johnupdated@example.com',
    };

    const mockUser = {
      id: '550e8400-e29b-41d4-a716-446655440000',
      name: 'John Doe Updated',
      email: 'johnupdated@example.com',
      passwordHash: 'hashedPassword123',
    };

    mockUsersService.updateUser.mockResolvedValue(mockUser);

    const updateUserResult = await controller.update(
      '550e8400-e29b-41d4-a716-446655440000',
      updateUserDto,
      mockReply,
    );

    expect(mockUsersService.updateUser).toHaveBeenCalledWith({
      id: '550e8400-e29b-41d4-a716-446655440000',
      ...updateUserDto,
    });
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

    const removeUserResult = await controller.remove(
      '550e8400-e29b-41d4-a716-446655440000',
      mockReply,
    );

    expect(mockUsersService.removeUser).toHaveBeenCalledWith({
      id: '550e8400-e29b-41d4-a716-446655440000',
    });
    expect(mockReply.status).toHaveBeenCalledWith(HttpStatus.OK);
    expect(removeUserResult).toEqual({
      statusCode: HttpStatus.OK,
      message: 'User removed successfully',
      success: true,
      data: undefined,
    });
  });
});
