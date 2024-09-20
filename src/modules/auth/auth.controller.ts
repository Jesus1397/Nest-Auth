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
  Res,
} from '@nestjs/common';
import { Response } from 'express';
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
    if (!loginDto.email || !loginDto.password) {
      throw new BadRequestException('❌ Email and password are required');
    }
    return this.authService.login(loginDto);
  }

  @Get('verify-email')
  async verifyEmail(@Query('email-verification-token') token: string) {
    if (!token) {
      throw new BadRequestException('❌ Email verification token is required');
    }
    return this.authService.verifyEmail(token);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body() dto: RequestResetPasswordDto) {
    if (!dto.email) {
      throw new BadRequestException('❌ Email is required');
    }
    return this.authService.requestPasswordReset(dto.email);
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    const { emailVerificationToken, newPassword } = dto;
    if (!emailVerificationToken || !newPassword) {
      throw new BadRequestException(
        '❌ Email verification token and new password are required',
      );
    }
    return this.authService.resetPassword(emailVerificationToken, newPassword);
  }

  @Post('2fa/verify')
  @UseGuards(JwtAuthGuard)
  async verifyTwoFactor(
    @Request() req: RequestWithUser,
    @Body() dto: TwoFactorDto,
  ) {
    const user = req.user;
    return this.authService.verifyTwoFactorCode(dto.token, user);
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

  @Get('2fa/generate')
  @UseGuards(JwtAuthGuard)
  async generateTwoFactorSecret(
    @Request() req: RequestWithUser,
    @Res() res: Response,
  ) {
    const user = req.user;
    return this.authService.generateTwoFactorSecret(user, res);
  }

  @Patch('admin-only')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  async adminOnly() {
    return { message: 'Acceso otorgado solo a administradores' };
  }

  @Patch('user/profile')
  @UseGuards(JwtAuthGuard)
  async updateUserProfile() {
    return { message: 'Actualización de perfil exitosa' };
  }
}
