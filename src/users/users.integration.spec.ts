import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TypeOrmModule } from '@nestjs/typeorm';
import type { FastifyReply } from 'fastify';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { User, UserRole } from './entities/user.entity';
import { TestDatabaseModule } from '../common/test/test-database.module';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

describe('Users Integration Tests', () => {
  let app: TestingModule;
  let usersController: UsersController;
  let usersService: UsersService;
  let usersRepository: Repository<User>;
  let mockReply: FastifyReply;

  beforeAll(async () => {
    app = await Test.createTestingModule({
      imports: [TestDatabaseModule, TypeOrmModule.forFeature([User])],
      controllers: [UsersController],
      providers: [UsersService],
    }).compile();

    usersController = app.get<UsersController>(UsersController);
    usersService = app.get<UsersService>(UsersService);
    usersRepository = app.get<Repository<User>>(getRepositoryToken(User));

    // Initialize the application
    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  beforeEach(async () => {
    // Clean database before each test - delete all users (CASCADE will handle related records)
    const allUsers = await usersRepository.find();
    if (allUsers.length > 0) {
      await usersRepository.remove(allUsers);
    }

    // Initialize mock reply
    mockReply = {
      status: jest.fn().mockReturnThis(),
    } as unknown as FastifyReply;
  });

  describe('User Creation', () => {
    it('should create a user successfully through controller', async () => {
      const createUserDto: CreateUserDto = {
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedPassword123',
        role: UserRole.CLIENT,
      };

      const createUserResult = await usersController.create(createUserDto, mockReply);

      expect(createUserResult.success).toBe(true);
      expect(createUserResult.data).toHaveProperty('id');
      expect(createUserResult.data.name).toBe(createUserDto.name);
      expect(createUserResult.data.email).toBe(createUserDto.email);
      expect(createUserResult.data.passwordHash).toBe(createUserDto.passwordHash);

      // Verify user was actually saved to database
      const savedUser = await usersRepository.findOneBy({ id: createUserResult.data.id });
      expect(savedUser).toBeTruthy();
      expect(savedUser?.email).toBe(createUserDto.email);
    });

    it('should create a user successfully through service', async () => {
      const createUserDto: CreateUserDto = {
        name: 'Service Test',
        email: 'service@example.com',
        passwordHash: 'hashedPassword123',
      };

      const createUserResult = await usersService.createUser(createUserDto);

      expect(createUserResult).toHaveProperty('id');
      expect(createUserResult.name).toBe(createUserDto.name);

      // Verify in database
      const count = await usersRepository.count();
      expect(count).toBe(1);
    });
  });

  describe('User Retrieval', () => {
    it('should return all users', async () => {
      // Arrange: Create test users directly in database
      const user1 = await usersRepository.save({
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedPassword123',
        role: UserRole.CLIENT,
      });

      const user2 = await usersRepository.save({
        name: 'Jane Smith',
        email: 'jane@example.com',
        passwordHash: 'hashedPassword456',
        role: UserRole.ANALYST,
      });

      // Act
      const findAllUsersResult = await usersController.findAll(mockReply);

      // Assert
      expect(findAllUsersResult.success).toBe(true);
      expect(findAllUsersResult.data).toHaveLength(2);
      expect(findAllUsersResult.data).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ id: user1.id, email: user1.email }),
          expect.objectContaining({ id: user2.id, email: user2.email }),
        ]),
      );
    });

    it('should return empty array when no users exist', async () => {
      const findAllUsersResult = await usersController.findAll(mockReply);

      expect(findAllUsersResult.data).toEqual([]);
      expect(findAllUsersResult.data).toHaveLength(0);
    });

    it('should return a specific user by id', async () => {
      // Arrange
      const user = await usersRepository.save({
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedPassword123',
        role: UserRole.CLIENT,
      });

      // Act
      const findOneUserResult = await usersController.findOne(user.id.toString(), mockReply);

      // Assert
      expect(findOneUserResult).toBeTruthy();
      expect(findOneUserResult?.data?.id).toBe(user.id);
      expect(findOneUserResult?.data?.email).toBe(user.email);
    });

    it('should return null for non-existent user', async () => {
      const findOneUserResult = await usersController.findOne(
        '550e8400-e29b-41d4-a716-446655440999',
        mockReply,
      );

      expect(findOneUserResult.data).toBeNull();
    });
  });

  describe('User Updates', () => {
    it('should update a user successfully', async () => {
      // Arrange
      const user = await usersRepository.save({
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedPassword123',
        role: UserRole.CLIENT,
      });

      const updateUserDto: UpdateUserDto = {
        name: 'John Doe Updated',
        email: 'johnupdated@example.com',
      };

      // Act
      const updateUserResult = await usersController.update(
        user.id.toString(),
        updateUserDto,
        mockReply,
      );

      // Assert
      expect(updateUserResult.data.name).toBe(updateUserDto.name);
      expect(updateUserResult.data.email).toBe(updateUserDto.email);
      expect(updateUserResult.data.role).toBe(user.role); // Should remain unchanged

      // Verify changes persisted in database
      const updatedUser = await usersRepository.findOneBy({ id: user.id });
      expect(updatedUser?.name).toBe(updateUserDto.name);
      expect(updatedUser?.email).toBe(updateUserDto.email);
    });
  });

  describe('User Deletion', () => {
    it('should remove a user successfully', async () => {
      // Arrange
      const user = await usersRepository.save({
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedPassword123',
        role: UserRole.CLIENT,
      });

      const initialCount = await usersRepository.count();
      expect(initialCount).toBe(1);

      // Act
      await usersController.remove(user.id.toString(), mockReply);

      // Assert
      const finalCount = await usersRepository.count();
      expect(finalCount).toBe(0);

      const deletedUser = await usersRepository.findOneBy({ id: user.id });
      expect(deletedUser).toBeNull();
    });
  });

  describe('End-to-End Workflow', () => {
    it('should perform complete CRUD operations', async () => {
      // Create
      const createUserDto: CreateUserDto = {
        name: 'E2E Test',
        email: 'e2e@example.com',
        passwordHash: 'hashedPassword123',
        role: UserRole.CLIENT,
      };

      const createdUser = await usersController.create(createUserDto, mockReply);
      expect(createdUser.data.id).toBeDefined();

      // Read One
      const foundUser = await usersController.findOne(createdUser.data.id.toString(), mockReply);
      expect(foundUser?.data?.email).toBe(createUserDto.email);

      // Read All
      const allUsers = await usersController.findAll(mockReply);
      expect(allUsers.data).toHaveLength(1);

      // Update
      const updateDto: UpdateUserDto = { name: 'E2E Test Updated' };
      const updatedUser = await usersController.update(
        createdUser.data.id.toString(),
        updateDto,
        mockReply,
      );
      expect(updatedUser.data.name).toBe('E2E Test Updated');

      // Delete
      await usersController.remove(createdUser.data.id.toString(), mockReply);
      const deletedUser = await usersController.findOne(createdUser.data.id.toString(), mockReply);
      expect(deletedUser.data).toBeNull();
    });
  });
});
