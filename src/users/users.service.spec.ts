import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';

describe('UsersService', () => {
  let service: UsersService;

  const mockRepository = {
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    findOneBy: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: getRepositoryToken(User),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should create and save a user successfully', async () => {
      const createUserPayload = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      };

      const mockUser = { id: 1, ...createUserPayload };

      mockRepository.create.mockReturnValue(mockUser);
      mockRepository.save.mockResolvedValue(mockUser);

      const result = await service.createUser(createUserPayload);

      expect(mockRepository.create).toHaveBeenCalledWith(createUserPayload);
      expect(mockRepository.save).toHaveBeenCalledWith(mockUser);
      expect(result).toEqual(mockUser);
    });

    it('should handle database errors during creation', async () => {
      const createUserPayload = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      };

      const mockUser = { id: 1, ...createUserPayload };
      mockRepository.create.mockReturnValue(mockUser);
      mockRepository.save.mockRejectedValue(new Error('Database error'));

      await expect(service.createUser(createUserPayload)).rejects.toThrow('Database error');
    });
  });

  describe('findAllUsers', () => {
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

      mockRepository.find.mockResolvedValue(mockUsers);

      const result = await service.findAllUsers();

      expect(mockRepository.find).toHaveBeenCalled();
      expect(result).toEqual(mockUsers);
      expect(result).toHaveLength(2);
    });

    it('should return empty array when no users exist', async () => {
      mockRepository.find.mockResolvedValue([]);

      const result = await service.findAllUsers();

      expect(mockRepository.find).toHaveBeenCalled();
      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
    });
  });

  describe('findUserById', () => {
    it('should return a user when found', async () => {
      const mockUser = {
        id: 1,
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      };

      mockRepository.findOneBy.mockResolvedValue(mockUser);

      const result = await service.findUserById({ id: 1 });

      expect(mockRepository.findOneBy).toHaveBeenCalledWith({ id: 1 });
      expect(result).toEqual(mockUser);
    });

    it('should return null when user not found', async () => {
      mockRepository.findOneBy.mockResolvedValue(null);

      const result = await service.findUserById({ id: 999 });

      expect(mockRepository.findOneBy).toHaveBeenCalledWith({ id: 999 });
      expect(result).toBeNull();
    });
  });

  describe('updateUser', () => {
    it('should update a user successfully', async () => {
      const updateUserPayload = {
        id: 1,
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

      mockRepository.update.mockResolvedValue({ affected: 1 });
      mockRepository.findOneBy.mockResolvedValue(mockUser);

      const result = await service.updateUser(updateUserPayload);

      expect(mockRepository.update).toHaveBeenCalledWith(1, {
        firstName: 'John Updated',
        email: 'johnupdated@example.com',
      });
      expect(mockRepository.findOneBy).toHaveBeenCalledWith({ id: 1 });
      expect(result).toEqual(mockUser);
    });

    it('should throw HttpExceptionCustom when user not found after update', async () => {
      const updateUserPayload = {
        id: 999,
        firstName: 'John Updated',
      };

      mockRepository.update.mockResolvedValue({ affected: 1 });
      mockRepository.findOneBy.mockResolvedValue(null);

      await expect(service.updateUser(updateUserPayload)).rejects.toThrow(HttpExceptionCustom);
    });
  });

  describe('removeUser', () => {
    it('should remove a user successfully', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 1 });

      await service.removeUser({ id: 1 });

      expect(mockRepository.delete).toHaveBeenCalledWith(1);
    });

    it('should handle deletion of non-existent user', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 0 });

      await service.removeUser({ id: 999 });

      expect(mockRepository.delete).toHaveBeenCalledWith(999);
    });
  });
});
