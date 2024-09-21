import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { UpdateProfileDto } from './dto/update-profile.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

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

    const { name, lastName, email, phone } = updateProfileDto;

    if (name) user.name = name;
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
