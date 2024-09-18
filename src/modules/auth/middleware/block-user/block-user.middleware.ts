import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { Response, NextFunction } from 'express';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { RequestWithUser } from 'src/common/interfaces/request-with-user.interface';
import { User } from '../../entities/user.entity';

@Injectable()
export class BlockUserMiddleware implements NestMiddleware {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async use(req: RequestWithUser, res: Response, next: NextFunction) {
    if (!req.user) {
      // Si no hay usuario en la solicitud, continuar
      return next();
    }

    const user = await this.userRepository.findOne({
      where: { id: req.user.id },
    });

    if (user?.isBlocked) {
      throw new UnauthorizedException('Tu cuenta está bloqueada');
    }

    next();
  }
}
