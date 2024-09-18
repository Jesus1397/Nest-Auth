import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class BlockUserMiddleware implements NestMiddleware {
  constructor(private readonly userRepository: UserRepository) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const user = await this.userRepository.findOne(req.user.id);

    if (user?.isBlocked) {
      throw new UnauthorizedException('Your account is blocked');
    }

    next();
  }
}
