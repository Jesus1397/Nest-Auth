import {
  Controller,
  Get,
  Query,
  BadRequestException,
  Body,
  Post,
  Patch,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RequestResetPasswordDto } from './dtos/request-reset-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { TwoFactorDto } from './dtos/two-factor.dto';
import { EnableTwoFactorDto } from './dtos/enable-2fa.dto';
import { JwtAuthGuard } from './guards/jwt-auth/jwt-auth.guard';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles/roles.guard';
import { RequestWithUser } from 'src/common/interfaces/request-with-user.interface';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    if (!token) {
      throw new BadRequestException('Token is required');
    }
    return this.authService.verifyEmail(token);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body() dto: RequestResetPasswordDto) {
    return this.authService.requestPasswordReset(dto.email);
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto.token, dto.newPassword);
  }

  @Post('2fa/verify')
  async verifyTwoFactor(@Body() dto: TwoFactorDto) {
    return this.authService.verifyTwoFactorCode(dto.token);
  }

  @Patch('2fa/enable')
  @UseGuards(JwtAuthGuard)
  async enableTwoFactor(
    @Request() req: RequestWithUser,
    @Body() dto: EnableTwoFactorDto,
  ) {
    const user = req.user;
    return this.authService.enableTwoFactor(user, dto.enable);
  }

  @Patch('admin-only')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin') // Solo accesible para administradores
  async adminOnly() {
    return { message: 'Este es un recurso solo para administradores' };
  }

  @Patch('user/profile')
  @UseGuards(JwtAuthGuard)
  async updateUserProfile() {
    return { message: 'Actualización de perfil exitosa' };
  }
}
