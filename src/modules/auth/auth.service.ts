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
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { v4 as uuidv4 } from 'uuid';
import * as nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<User> {
    const { email, password } = registerDto;
    const hashedPassword = await bcrypt.hash(password, 10);

    // Genera el token de verificación
    const emailVerificationToken = uuidv4();

    const user = this.userRepository.create({
      email,
      password: hashedPassword,
      emailVerificationToken,
    });

    const savedUser = await this.userRepository.save(user);

    // Enviar correo de verificación
    this.sendVerificationEmail(email, emailVerificationToken);

    return savedUser;
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
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

    const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

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
}
