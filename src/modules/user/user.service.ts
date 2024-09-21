import { Injectable, BadRequestException, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { UpdateProfileDto } from './dto/update-profile.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService implements OnModuleInit {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  async onModuleInit() {
    await this.ensureAdminUser();
  }

  async doesAdminExist(): Promise<boolean> {
    const admin = await this.userRepository.findOne({
      where: { roles: 'admin' },
    });
    return !!admin;
  }

  async createAdmin() {
    const adminExists = await this.doesAdminExist();
    if (!adminExists) {
      const adminUser = this.userRepository.create({
        firstName: 'Default',
        lastName: 'Admin',
        email: process.env.DEFAULT_ADMIN_EMAIL,
        password: bcrypt.hashSync(process.env.DEFAULT_ADMIN_PASSWORD, 10),
        roles: ['admin'],
      });

      await this.userRepository.save(adminUser);
      console.log('👑 Admin user created successfully');
    } else {
      console.log('✔️ Admin user already exists');
    }
  }

  async ensureAdminUser() {
    const adminExists = await this.doesAdminExist();
    if (!adminExists) {
      await this.createAdmin();
    } else {
      console.log('✔️ Admin user already exists');
    }
  }

  async getUserInfo(userId: string) {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new BadRequestException('❌ User not found');
    }

    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      phoneNumber: user.phoneNumber,
      roles: user.roles,
      isTwoFactorEnabled: user.isTwoFactorEnabled,
      emailVerified: user.emailVerified,
    };
  }

  async updateProfile(
    userId: string,
    updateProfileDto: UpdateProfileDto,
  ): Promise<object> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new BadRequestException('❌ User not found');
    }

    const { firstName, lastName, email, phone } = updateProfileDto;

    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (email) user.email = email;
    if (phone) user.phone = phone;

    const updatedUser = await this.userRepository.save(user);

    return {
      message: '👤 Profile updated successfully',
      user: updatedUser,
    };
  }

  async grantAdminRole(userId: string) {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new BadRequestException('❌ User not found');
    }

    user.roles.push('admin');
    await this.userRepository.save(user);

    return { message: '🛡️ Admin role granted successfully', user };
  }

  async getAllUsers() {
    const users = await this.userRepository.find();
    return { message: '👥 Users retrieved successfully', users };
  }

  async deleteUser(userId: string) {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new BadRequestException('❌ User not found');
    }

    await this.userRepository.remove(user);
    return { message: '🗑️ User deleted successfully' };
  }
}
