import {
  Controller,
  Get,
  Patch,
  Param,
  Delete,
  UseGuards,
  Request,
  Body,
  BadRequestException,
} from '@nestjs/common';
import { Roles } from '../../common/decorators/roles.decorator';
import { RequestWithUser } from 'src/common/interfaces/request-with-user.interface';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { UserService } from './user.service';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles/roles.guard';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getUserInfo(@Request() req: RequestWithUser) {
    return this.userService.getUserInfo(req.user.id);
  }

  @Patch('update-profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(
    @Request() req: RequestWithUser,
    @Body() updateProfileDto: UpdateProfileDto,
  ) {
    const userId = req.user.id;

    if (updateProfileDto.email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(updateProfileDto.email)) {
        throw new BadRequestException('❌ Invalid email format');
      }
    }

    return this.userService.updateProfile(userId, updateProfileDto);
  }

  @Patch('admin/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  async grantAdminRole(@Param('id') userId: string) {
    return this.userService.grantAdminRole(userId);
  }

  @Get('admin/all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  async getAllUsers() {
    return this.userService.getAllUsers();
  }

  @Delete('admin/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  async deleteUser(@Param('id') userId: string) {
    return this.userService.deleteUser(userId);
  }
}
