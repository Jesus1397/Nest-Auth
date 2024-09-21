import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtNotLoggedInGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const request: Request = context.switchToHttp().getRequest();
    const authHeader = request.headers['authorization'];

    if (authHeader) {
      const token = authHeader.split(' ')[1];

      try {
        const user = this.jwtService.verify(token);

        if (user) {
          throw new UnauthorizedException('❌ You are already logged in');
        }
      } catch (error) {
        console.log(error);
      }
    }

    return true;
  }
}
