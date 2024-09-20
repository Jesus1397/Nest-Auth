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
      const token = authHeader.split(' ')[1]; // Extraer el token del header

      try {
        // Verificar si el token es válido
        const user = this.jwtService.verify(token);

        // Si el token es válido y el usuario está autenticado, lanzar error
        if (user) {
          throw new UnauthorizedException('❌ You are already logged in');
        }
      } catch (error) {
        // Si el token no es válido o ha expirado, permitir el login
        // No lanzamos excepción aquí ya que el usuario podrá volver a iniciar sesión
        console.log(error);
      }
    }

    return true; // Permite el acceso si no hay token o el token es inválido
  }
}
