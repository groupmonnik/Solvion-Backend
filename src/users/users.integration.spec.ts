import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TypeOrmModule } from '@nestjs/typeorm';
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
  });

  describe('User Creation', () => {
    it('should create a user successfully through controller', async () => {
      const createUserDto: CreateUserDto = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
      };

      const result = await usersController.create(createUserDto);

      expect(result).toHaveProperty('id');
      expect(result.firstName).toBe(createUserDto.firstName);
      expect(result.lastName).toBe(createUserDto.lastName);
      expect(result.email).toBe(createUserDto.email);
      expect(result.password).toBe(createUserDto.password);

      // Verify user was actually saved to database
      const savedUser = await usersRepository.findOneBy({ id: result.id });
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

      const result = await usersService.createUser(createUserDto);

      expect(result).toHaveProperty('id');
      expect(result.firstName).toBe(createUserDto.firstName);

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
      const result = await usersController.findAll();

      // Assert
      expect(result).toHaveLength(2);
      expect(result).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ id: user1.id, email: user1.email }),
          expect.objectContaining({ id: user2.id, email: user2.email }),
        ]),
      );
    });

    it('should return empty array when no users exist', async () => {
      const result = await usersController.findAll();

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
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
      const result = await usersController.findOne(user.id.toString());

      // Assert
      expect(result).toBeTruthy();
      expect(result?.id).toBe(user.id);
      expect(result?.email).toBe(user.email);
    });

    it('should return null for non-existent user', async () => {
      const result = await usersController.findOne('999');

      expect(result).toBeNull();
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
      const result = await usersController.update(user.id.toString(), updateUserDto);

      // Assert
      expect(result.firstName).toBe(updateUserDto.firstName);
      expect(result.email).toBe(updateUserDto.email);
      expect(result.lastName).toBe(user.lastName); // Should remain unchanged

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
      await usersController.remove(user.id.toString());

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

      const createdUser = await usersController.create(createUserDto);
      expect(createdUser.id).toBeDefined();

      // Read One
      const foundUser = await usersController.findOne(createdUser.id.toString());
      expect(foundUser?.email).toBe(createUserDto.email);

      // Read All
      const allUsers = await usersController.findAll();
      expect(allUsers).toHaveLength(1);

      // Update
      const updateDto: UpdateUserDto = { firstName: 'E2E Updated' };
      const updatedUser = await usersController.update(createdUser.id.toString(), updateDto);
      expect(updatedUser.firstName).toBe('E2E Updated');

      // Delete
      await usersController.remove(createdUser.id.toString());
      const deletedUser = await usersController.findOne(createdUser.id.toString());
      expect(deletedUser).toBeNull();
    });
  });
});
