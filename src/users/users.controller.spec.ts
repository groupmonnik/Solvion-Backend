import { Test, TestingModule } from '@nestjs/testing';
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

    const result = await controller.create(createUserDto);

    expect(mockUsersService.createUser).toHaveBeenCalledWith(createUserDto);
    expect(result).toEqual(mockUser);
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

    const result = await controller.findAll();

    expect(mockUsersService.findAllUsers).toHaveBeenCalled();
    expect(result).toEqual(mockUsers);
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

    const result = await controller.findOne('1');

    expect(mockUsersService.findUserById).toHaveBeenCalledWith({ id: 1 });
    expect(result).toEqual(mockUser);
  });

  it('should update a user', async () => {
    const updateUserDto: UpdateUserDto = {
      firstName: 'John Updated',
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

    const result = await controller.update('1', updateUserDto);

    expect(mockUsersService.updateUser).toHaveBeenCalledWith({ id: 1, ...updateUserDto });
    expect(result).toEqual(mockUser);
  });

  it('should remove a user', async () => {
    mockUsersService.removeUser.mockResolvedValue(undefined);

    await controller.remove('1');

    expect(mockUsersService.removeUser).toHaveBeenCalledWith({ id: 1 });
  });
});
