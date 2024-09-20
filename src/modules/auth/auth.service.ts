import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
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
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  private async sendVerificationEmail(email: string, token: string) {
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

  private async sendPasswordResetEmail(email: string, token: string) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const resetLink = `${process.env.FRONTEND_URL}/auth/reset-password?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Solicitud de cambio de contraseña',
      text: `Haz clic en el siguiente enlace para cambiar tu contraseña: ${resetLink}`,
    };

    await transporter.sendMail(mailOptions);
  }

  private async sendTwoFactorCode(email: string, code: string) {
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

  async register(registerDto: RegisterDto): Promise<User> {
    const { email, password } = registerDto;
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

    return savedUser;
  }

  async login(loginDto: LoginDto) {
    try {
      const { email, password } = loginDto;
      console.log('Login attempt:', email);

      const user = await this.userRepository.findOne({ where: { email } });
      console.log('User found:', user);

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      console.log('Password match:', passwordMatch);

      if (!passwordMatch) {
        throw new UnauthorizedException('Invalid password');
      }

      // Si pasa las verificaciones, genera el token
      const payload = { email: user.email, sub: user.id };
      console.log('JWT Payload:', payload);

      const token = this.jwtService.sign(payload);
      console.log('Generated JWT:', token);

      return { access_token: token };
    } catch (error) {
      console.error('Error during login:', error); // Log completo del error
      throw new InternalServerErrorException({
        message: 'Error during login process',
        details: error.message,
      });
    }
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
    console.log('Buscando usuario con email:', email);
    const user = await this.userRepository.findOne({
      where: { email: email.toLowerCase() },
    });
    console.log('Usuario encontrado:', user);

    if (!user) {
      throw new BadRequestException('Email not found');
    }

    const resetToken = uuidv4();
    user.emailVerificationToken = resetToken; // Usaremos el mismo campo de verificación de email
    await this.userRepository.save(user);

    // Enviar el correo con el token
    this.sendPasswordResetEmail(user.email, resetToken);
  }

  async resetPassword(token: string, newPassword: string): Promise<string> {
    try {
      console.log('Token recibido:', token);
      console.log('Nueva contraseña recibida:', newPassword);

      const user = await this.userRepository.findOne({
        where: { emailVerificationToken: token },
      });

      if (!user) {
        console.log('Usuario no encontrado con este token.');
        throw new BadRequestException('Invalid token');
      }

      console.log('Usuario encontrado:', user.email);

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      user.emailVerificationToken = null;

      await this.userRepository.save(user);

      console.log('Contraseña cambiada con éxito para el usuario:', user.email);

      return 'Password cambiada con éxito'; // Mensaje de éxito
    } catch (error) {
      console.error('Error al restablecer la contraseña:', error.message); // Log de error para depuración
      throw new InternalServerErrorException(
        'Error al restablecer la contraseña',
      );
    }
  }

  async verifyTwoFactorCode(token: string, user: User): Promise<any> {
    // Verifica si el usuario tiene 2FA habilitado
    if (!user.isTwoFactorEnabled || !user.twoFactorSecret) {
      throw new UnauthorizedException('2FA is not enabled for this user');
    }

    // Verifica el código TOTP usando el secreto almacenado en el usuario
    const isCodeValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret, // Secreto 2FA del usuario
      encoding: 'base32',
      token, // Código TOTP que el usuario envió
    });

    if (!isCodeValid) {
      throw new UnauthorizedException('Invalid 2FA token');
    }

    // Si el código es válido, genera un nuevo JWT
    const payload = { email: user.email, sub: user.id };
    const jwt = this.jwtService.sign(payload);

    return { access_token: jwt };
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
