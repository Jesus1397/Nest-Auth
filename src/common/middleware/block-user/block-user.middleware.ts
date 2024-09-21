import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Request, Response, NextFunction } from 'express';
import { User } from 'src/modules/user/entities/user.entity';

@Injectable()
export class BlockUserMiddleware implements NestMiddleware {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const user = await this.userRepository.findOne({
      where: { id: req.user?.id },
    });

    if (user?.isBlocked) {
      throw new UnauthorizedException('Your account is blocked');
    }

    next();
  }
}
