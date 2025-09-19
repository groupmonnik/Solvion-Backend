import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TypeOrmModule } from '@nestjs/typeorm';
import type { FastifyReply } from 'fastify';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
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
    // Clean database before each test
    await usersRepository.clear();

    // Initialize mock reply
    mockReply = {
      status: jest.fn().mockReturnThis(),
    } as unknown as FastifyReply;
  });

  describe('User Creation', () => {
    it('should create a user successfully through controller', async () => {
      const createUserDto: CreateUserDto = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      };

      const createUserResult = await usersController.create(createUserDto, mockReply);

      expect(createUserResult.success).toBe(true);
      expect(createUserResult.data).toHaveProperty('id');
      expect(createUserResult.data.firstName).toBe(createUserDto.firstName);
      expect(createUserResult.data.lastName).toBe(createUserDto.lastName);
      expect(createUserResult.data.email).toBe(createUserDto.email);
      expect(createUserResult.data.password).toBe(createUserDto.password);

      // Verify user was actually saved to database
      const savedUser = await usersRepository.findOneBy({ id: createUserResult.data.id });
      expect(savedUser).toBeTruthy();
      expect(savedUser?.email).toBe(createUserDto.email);
    });

    it('should create a user successfully through service', async () => {
      const createUserDto: CreateUserDto = {
        firstName: 'Service',
        lastName: 'Test',
        email: 'service@example.com',
        password: 'password123',
      };

      const createUserResult = await usersService.createUser(createUserDto);

      expect(createUserResult).toHaveProperty('id');
      expect(createUserResult.firstName).toBe(createUserDto.firstName);

      // Verify in database
      const count = await usersRepository.count();
      expect(count).toBe(1);
    });
  });

  describe('User Retrieval', () => {
    it('should return all users', async () => {
      // Arrange: Create test users directly in database
      const user1 = await usersRepository.save({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      });

      const user2 = await usersRepository.save({
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane@example.com',
        password: 'password456',
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
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      });

      // Act
      const findOneUserResult = await usersController.findOne(user.id.toString(), mockReply);

      // Assert
      expect(findOneUserResult).toBeTruthy();
      expect(findOneUserResult?.data?.id).toBe(user.id);
      expect(findOneUserResult?.data?.email).toBe(user.email);
    });

    it('should return null for non-existent user', async () => {
      const findOneUserResult = await usersController.findOne('999', mockReply);

      expect(findOneUserResult.data).toBeNull();
    });
  });

  describe('User Updates', () => {
    it('should update a user successfully', async () => {
      // Arrange
      const user = await usersRepository.save({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      });

      const updateUserDto: UpdateUserDto = {
        firstName: 'John Updated',
        email: 'johnupdated@example.com',
      };

      // Act
      const updateUserResult = await usersController.update(
        user.id.toString(),
        updateUserDto,
        mockReply,
      );

      // Assert
      expect(updateUserResult.data.firstName).toBe(updateUserDto.firstName);
      expect(updateUserResult.data.email).toBe(updateUserDto.email);
      expect(updateUserResult.data.lastName).toBe(user.lastName); // Should remain unchanged

      // Verify changes persisted in database
      const updatedUser = await usersRepository.findOneBy({ id: user.id });
      expect(updatedUser?.firstName).toBe(updateUserDto.firstName);
      expect(updatedUser?.email).toBe(updateUserDto.email);
    });
  });

  describe('User Deletion', () => {
    it('should remove a user successfully', async () => {
      // Arrange
      const user = await usersRepository.save({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
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
        firstName: 'E2E',
        lastName: 'Test',
        email: 'e2e@example.com',
        password: 'password123',
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
      const updateDto: UpdateUserDto = { firstName: 'E2E Updated' };
      const updatedUser = await usersController.update(
        createdUser.data.id.toString(),
        updateDto,
        mockReply,
      );
      expect(updatedUser.data.firstName).toBe('E2E Updated');

      // Delete
      await usersController.remove(createdUser.data.id.toString(), mockReply);
      const deletedUser = await usersController.findOne(createdUser.data.id.toString(), mockReply);
      expect(deletedUser.data).toBeNull();
    });
  });
});
