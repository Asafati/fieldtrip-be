import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { TokenExpiredError } from 'jsonwebtoken'; // Import tambahan untuk menangani expired token

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    // Skip public api
    if (['/api/auth/login', '/api/auth/register'].includes(request.url)) {
      return true;
    }
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException('Token is missing');
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });
      // Menambahkan payload ke request agar bisa diakses di route handler
      request['user'] = payload;

      // Optional: Memeriksa roles (bisa disesuaikan dengan peran yang diperlukan)
      if (!this.checkRoles(payload)) {
        throw new UnauthorizedException('Insufficient roles');
      }
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        throw new UnauthorizedException('Token has expired, please log in again');
      }
      throw new UnauthorizedException('Invalid token');
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authorization = request.headers.authorization;
    if (!authorization) {
      throw new UnauthorizedException('Authorization header is missing');
    }

    const [type, token] = authorization.split(' ');
    if (type !== 'Bearer' || !token) {
      throw new UnauthorizedException('Invalid authorization format');
    }

    return token;
  }

  private checkRoles(payload: any): boolean {
    // Logika untuk memeriksa role (bisa disesuaikan sesuai dengan aplikasi kamu)
    const requiredRoles = ['admin']; // Misal, hanya admin yang bisa mengakses
    return requiredRoles.some(role => payload.roles?.includes(role));
  }
}
