import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './entities/user.entity';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';
import { v4 as uuidv4 } from 'uuid';
import * as nodemailer from 'nodemailer';
import * as speakeasy from 'speakeasy'; // Para generar códigos de doble factor
import * as qrcode from 'qrcode';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<User> {
    const { email, password } = registerDto;
    const hashedPassword = await bcrypt.hash(password, 10);

    const emailVerificationToken = uuidv4();

    const user = this.userRepository.create({
      email,
      password: hashedPassword,
      emailVerificationToken,
      roles: ['user'], // Asignar rol por defecto
    });

    const savedUser = await this.userRepository.save(user);

    this.sendVerificationEmail(email, emailVerificationToken);

    return savedUser;
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Si el 2FA está habilitado, generamos un código temporal
    if (user.isTwoFactorEnabled) {
      const twoFactorCode = speakeasy.totp({
        secret: process.env.TWO_FACTOR_SECRET, // Puede ser único por usuario o compartido
        encoding: 'base32',
      });

      // Guardar el código 2FA en la base de datos temporalmente (dependiendo de la lógica)
      user.twoFactorCode = twoFactorCode;
      await this.userRepository.save(user);

      // Enviar el código por email (o notificación)
      this.sendTwoFactorCode(user.email, twoFactorCode);

      return {
        message: 'Se ha enviado un código 2FA a tu email',
      };
    }

    const payload = { email: user.email, sub: user.id };
    const token = this.jwtService.sign(payload);

    return {
      access_token: token,
    };
  }

  async sendVerificationEmail(email: string, token: string) {
    const transporter = nodemailer.createTransport({
      service: 'gmail', // O el servicio que prefieras
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const verificationLink = `${process.env.FRONTEND_URL}/auth/verify-email?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Confirmación de correo electrónico',
      text: `Haz clic en el siguiente enlace para verificar tu cuenta: ${verificationLink}`,
    };

    await transporter.sendMail(mailOptions);
  }

  async verifyEmail(token: string): Promise<string> {
    const user = await this.userRepository.findOne({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      throw new BadRequestException('Invalid token');
    }

    user.emailVerified = true;
    user.emailVerificationToken = null; // Elimina el token después de la verificación

    await this.userRepository.save(user);

    return 'Email verificado con éxito';
  }

  async requestPasswordReset(email: string) {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      throw new BadRequestException('Email not found');
    }

    const resetToken = uuidv4();
    user.emailVerificationToken = resetToken; // Usaremos el mismo campo de verificación de email
    await this.userRepository.save(user);

    // Enviar el correo con el token
    this.sendPasswordResetEmail(user.email, resetToken);
  }

  async sendPasswordResetEmail(email: string, token: string) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Solicitud de cambio de contraseña',
      text: `Haz clic en el siguiente enlace para cambiar tu contraseña: ${resetLink}`,
    };

    await transporter.sendMail(mailOptions);
  }

  async resetPassword(token: string, newPassword: string) {
    const user = await this.userRepository.findOne({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      throw new BadRequestException('Invalid token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.emailVerificationToken = null; // Elimina el token una vez se cambia la contraseña

    await this.userRepository.save(user);

    return 'Password cambiada con éxito';
  }

  async sendTwoFactorCode(email: string, code: string) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Código de autenticación de doble factor',
      text: `Tu código 2FA es: ${code}`,
    };

    await transporter.sendMail(mailOptions);
  }

  async verifyTwoFactorCode(token: string): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { twoFactorCode: token },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid 2FA token');
    }

    // Generar JWT una vez verificado el 2FA
    const payload = { email: user.email, sub: user.id };
    const jwt = this.jwtService.sign(payload);

    // Limpiar el código 2FA para que no se pueda usar de nuevo
    user.twoFactorCode = null;
    await this.userRepository.save(user);

    return {
      access_token: jwt,
    };
  }

  async enableTwoFactor(user: User, enable: boolean) {
    user.isTwoFactorEnabled = enable;
    await this.userRepository.save(user);

    return { message: `2FA ${enable ? 'enabled' : 'disabled'} successfully` };
  }

  async generateTwoFactorSecret(user: User) {
    const secret = speakeasy.generateSecret();

    // Genera el código QR
    const otpAuthUrl = speakeasy.otpauthURL({
      secret: secret.base32,
      label: `MyApp (${user.email})`,
      encoding: 'base32',
    });

    // Almacena el secreto 2FA en la base de datos
    user.twoFactorSecret = secret.base32;
    await this.userRepository.save(user);

    return qrcode.toDataURL(otpAuthUrl); // Devuelve el QR como imagen
  }
}
