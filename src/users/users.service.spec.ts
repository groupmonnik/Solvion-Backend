import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { User, UserRole } from './entities/user.entity';
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
        name: 'John Doe',
        email: 'john@example.com',
        password: 'hashedPassword123',
        role: UserRole.CLIENT,
      };

      const mockUser = { id: '550e8400-e29b-41d4-a716-446655440000', ...createUserPayload };

      mockRepository.create.mockReturnValue(mockUser);
      mockRepository.save.mockResolvedValue(mockUser);

      const result = await service.createUser(createUserPayload);

      expect(mockRepository.create).toHaveBeenCalledWith(createUserPayload);
      expect(mockRepository.save).toHaveBeenCalledWith(mockUser);
      expect(result).toEqual(mockUser);
    });

    it('should handle database errors during creation', async () => {
      const createUserPayload = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'hashedPassword123',
      };

      const mockUser = { id: '550e8400-e29b-41d4-a716-446655440000', ...createUserPayload };
      mockRepository.create.mockReturnValue(mockUser);
      mockRepository.save.mockRejectedValue(new Error('Database error'));

      await expect(service.createUser(createUserPayload)).rejects.toThrow('Database error');
    });
  });

  describe('findAllUsers', () => {
    it('should return all users', async () => {
      const mockUsers = [
        {
          id: '550e8400-e29b-41d4-a716-446655440000',
          name: 'John Doe',
          email: 'john@example.com',
          password: 'hashedPassword123',
          role: UserRole.CLIENT,
        },
        {
          id: '550e8400-e29b-41d4-a716-446655440001',
          name: 'Jane Smith',
          email: 'jane@example.com',
          password: 'hashedPassword456',
          role: UserRole.ANALYST,
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
        id: '550e8400-e29b-41d4-a716-446655440000',
        name: 'John Doe',
        email: 'john@example.com',
        password: 'hashedPassword123',
        role: UserRole.CLIENT,
      };

      mockRepository.findOneBy.mockResolvedValue(mockUser);

      const result = await service.findUserById({ id: '550e8400-e29b-41d4-a716-446655440000' });

      expect(mockRepository.findOneBy).toHaveBeenCalledWith({
        id: '550e8400-e29b-41d4-a716-446655440000',
      });
      expect(result).toEqual(mockUser);
    });

    it('should return null when user not found', async () => {
      mockRepository.findOneBy.mockResolvedValue(null);

      const result = await service.findUserById({ id: '550e8400-e29b-41d4-a716-446655440999' });

      expect(mockRepository.findOneBy).toHaveBeenCalledWith({
        id: '550e8400-e29b-41d4-a716-446655440999',
      });
      expect(result).toBeNull();
    });
  });

  describe('updateUser', () => {
    it('should update a user successfully', async () => {
      const updateUserPayload = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        name: 'John Doe Updated',
        email: 'johnupdated@example.com',
      };

      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        name: 'John Doe Updated',
        email: 'johnupdated@example.com',
        password: 'hashedPassword123',
        role: UserRole.CLIENT,
      };

      mockRepository.update.mockResolvedValue({ affected: 1 });
      mockRepository.findOneBy.mockResolvedValue(mockUser);

      const result = await service.updateUser(updateUserPayload);

      expect(mockRepository.update).toHaveBeenCalledWith('550e8400-e29b-41d4-a716-446655440000', {
        name: 'John Doe Updated',
        email: 'johnupdated@example.com',
      });
      expect(mockRepository.findOneBy).toHaveBeenCalledWith({
        id: '550e8400-e29b-41d4-a716-446655440000',
      });
      expect(result).toEqual(mockUser);
    });

    it('should throw HttpExceptionCustom when user not found after update', async () => {
      const updateUserPayload = {
        id: '550e8400-e29b-41d4-a716-446655440999',
        name: 'John Doe Updated',
      };

      mockRepository.update.mockResolvedValue({ affected: 1 });
      mockRepository.findOneBy.mockResolvedValue(null);

      await expect(service.updateUser(updateUserPayload)).rejects.toThrow(HttpExceptionCustom);
    });
  });

  describe('removeUser', () => {
    it('should remove a user successfully', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 1 });

      await service.removeUser({ id: '550e8400-e29b-41d4-a716-446655440000' });

      expect(mockRepository.delete).toHaveBeenCalledWith('550e8400-e29b-41d4-a716-446655440000');
    });

    it('should handle deletion of non-existent user', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 0 });

      await service.removeUser({ id: '550e8400-e29b-41d4-a716-446655440999' });

      expect(mockRepository.delete).toHaveBeenCalledWith('550e8400-e29b-41d4-a716-446655440999');
    });
  });
});
