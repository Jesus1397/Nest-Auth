import {
  Controller,
  Get,
  Query,
  BadRequestException,
  Body,
  Post,
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
import { RequestWithUser } from 'src/common/interfaces/request-with-user.interface';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';
import { JwtNotLoggedInGuard } from './guards/jwt-not-logged-in/jwt-not-logged-in.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    const { email, password } = registerDto;

    if (!email || !password) {
      throw new BadRequestException('❌ Email and password are required');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('❌ Invalid email format');
    }

    if (password.length < 6) {
      throw new BadRequestException(
        '❌ Password must be at least 6 characters long',
      );
    }

    return this.authService.register(registerDto);
  }

  @Post('login')
  @UseGuards(JwtNotLoggedInGuard)
  async login(@Body() loginDto: LoginDto) {
    const { email, password } = loginDto;

    if (!email || !password) {
      throw new BadRequestException('❌ Email and password are required');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('❌ Invalid email format');
    }

    return this.authService.login(loginDto);
  }

  @Get('verify-email')
  async verifyEmail(@Query('email-verification-token') token: string) {
    if (!token) {
      throw new BadRequestException('❌ Email verification token is required');
    }

    if (token.length < 20) {
      throw new BadRequestException('❌ Invalid verification token format');
    }

    return this.authService.verifyEmail(token);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body() dto: RequestResetPasswordDto) {
    const { email } = dto;

    if (!email) {
      throw new BadRequestException('❌ Email is required');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('❌ Invalid email format');
    }

    return this.authService.requestPasswordReset(email);
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    const { emailVerificationToken, newPassword } = dto;

    if (!emailVerificationToken || !newPassword) {
      throw new BadRequestException(
        '❌ Email verification token and new password are required',
      );
    }

    if (emailVerificationToken.length < 20) {
      throw new BadRequestException('❌ Invalid verification token format');
    }

    if (newPassword.length < 6) {
      throw new BadRequestException(
        '❌ Password must be at least 6 characters long',
      );
    }

    return this.authService.resetPassword(emailVerificationToken, newPassword);
  }

  @Post('2fa/verify')
  @UseGuards(JwtAuthGuard)
  async verifyTwoFactor(
    @Body() twoFactorDto: TwoFactorDto,
    @Request() req: RequestWithUser,
  ) {
    const { token } = twoFactorDto;

    if (!token) {
      throw new BadRequestException('❌ 2FA token is required');
    }

    if (token.length !== 6) {
      throw new BadRequestException('❌ 2FA token must be 6 digits');
    }

    return this.authService.verifyTwoFactorCode(token, req.user);
  }

  @Post('2fa/enable')
  @UseGuards(JwtAuthGuard)
  async enableTwoFactor(
    @Body() enableTwoFactorDto: EnableTwoFactorDto,
    @Request() req: RequestWithUser,
  ) {
    const { enable } = enableTwoFactorDto;

    if (typeof enable !== 'boolean') {
      throw new BadRequestException('❌ "enable" must be a boolean');
    }

    return this.authService.enableTwoFactor(req.user, enable);
  }

  @Get('2fa/generate')
  @UseGuards(JwtAuthGuard)
  async generateTwoFactorSecret(
    @Request() req: RequestWithUser,
    @Res() res: Response,
  ) {
    if (!req.user) {
      throw new BadRequestException('❌ User must be authenticated');
    }

    return this.authService.generateTwoFactorSecret(req.user, res);
  }
}
