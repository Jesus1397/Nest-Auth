import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Response } from 'express';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from '../user/entities/user.entity';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';
import { v4 as uuidv4 } from 'uuid';
import * as nodemailer from 'nodemailer';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<object> {
    const { email, password, confirmPassword } = registerDto;

    if (password !== confirmPassword) {
      throw new BadRequestException('❌ Passwords do not match');
    }

    try {
      const existingUser = await this.userRepository.findOne({
        where: { email },
      });
      if (existingUser) {
        throw new BadRequestException('❌ User already exists with this email');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const emailVerificationToken = uuidv4();

      const user = this.userRepository.create({
        email,
        password: hashedPassword,
        emailVerificationToken,
        roles: ['user'],
      });

      const savedUser = await this.userRepository.save(user);
      this.sendVerificationEmail(email, emailVerificationToken);

      return {
        message: '📧 Registration successful. Verification email sent.',
        user: savedUser,
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: '⚠️ Error during the registration process',
        details: error.message,
      });
    }
  }

  async login(loginDto: LoginDto) {
    try {
      const { email, password } = loginDto;
      const user = await this.userRepository.findOne({ where: { email } });

      if (!user) {
        throw new UnauthorizedException('❌ User not found');
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        throw new UnauthorizedException('🔑 Invalid password');
      }

      const payload = { email: user.email, sub: user.id };
      const token = this.jwtService.sign(payload);

      return { message: '🔐 Login successful', access_token: token };
    } catch (error) {
      throw new InternalServerErrorException({
        message: '⚠️ Error during login process',
        details: error.message,
      });
    }
  }

  async verifyEmail(token: string): Promise<object> {
    const user = await this.userRepository.findOne({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      throw new BadRequestException('❌ Invalid token');
    }

    user.emailVerified = true;
    user.emailVerificationToken = null;

    await this.userRepository.save(user);

    return { message: '📧 Email successfully verified' };
  }

  async requestPasswordReset(email: string): Promise<object> {
    const user = await this.userRepository.findOne({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      throw new BadRequestException('📭 Email not found');
    }

    const resetToken = uuidv4();
    user.emailVerificationToken = resetToken;
    await this.userRepository.save(user);

    this.sendPasswordResetEmail(user.email, resetToken);

    return { message: '✉️ Password reset email sent' };
  }

  async resetPassword(token: string, newPassword: string): Promise<object> {
    const user = await this.userRepository.findOne({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      throw new BadRequestException('🔒 Invalid token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.emailVerificationToken = null;

    await this.userRepository.save(user);

    return { message: '🔑 Password changed successfully' };
  }

  async verifyTwoFactorCode(token: string, user: User): Promise<object> {
    if (!user.isTwoFactorEnabled || !user.twoFactorSecret) {
      throw new UnauthorizedException('❌ 2FA is not enabled for this user');
    }

    const isCodeValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
    });

    if (!isCodeValid) {
      throw new UnauthorizedException('🔐 Invalid 2FA token');
    }

    const payload = { email: user.email, sub: user.id };
    const jwt = this.jwtService.sign(payload);

    return { message: '✅ 2FA verified', access_token: jwt };
  }

  async enableTwoFactor(user: User, enable: boolean): Promise<object> {
    user.isTwoFactorEnabled = enable;
    await this.userRepository.save(user);

    return {
      message: `2FA ${enable ? '🔒 enabled' : '🔓 disabled'} successfully`,
    };
  }

  async generateTwoFactorSecret(user: User, res: Response) {
    const secret = speakeasy.generateSecret();

    const otpAuthUrl = speakeasy.otpauthURL({
      secret: secret.base32,
      label: `MyApp (${user.email})`,
      encoding: 'base32',
    });

    user.twoFactorSecret = secret.base32;
    await this.userRepository.save(user);

    const qrCodeBuffer = await qrcode.toBuffer(otpAuthUrl);

    res.setHeader('Content-Type', 'image/png');
    res.send(qrCodeBuffer);
  }

  async adminAccessOnly() {
    return { message: '🔐 Admin access granted' };
  }

  private async sendVerificationEmail(email: string, token: string) {
    await this.sendEmail(
      email,
      'Email Verification',
      `Click the following link to verify your account: ${process.env.FRONTEND_URL}/auth/verify-email?email-verification-token=${token}`,
    );
  }

  private async sendPasswordResetEmail(email: string, token: string) {
    await this.sendEmail(
      email,
      'Password Reset Request',
      `Email-verification-token: <strong>${token}</strong>
      Click the following link to reset your password: ${process.env.FRONTEND_URL}/auth/reset-password?email-verification-token=${token}`,
    );
  }

  private async sendEmail(to: string, subject: string, text: string) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to,
      subject,
      text,
    };

    await transporter.sendMail(mailOptions);
  }
}
