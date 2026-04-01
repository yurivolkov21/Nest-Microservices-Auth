import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RequestWithUser } from '../interfaces/request-with-user.interface';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>(
      'roles',
      ctx.getHandler(),
    );

    // Nếu không yêu cầu role cụ thể, cho phép truy cập
    if (!requiredRoles?.length) return true;

    const req = ctx.switchToHttp().getRequest<RequestWithUser>();
    const user = req.user; // Lấy từ JwtGuard đã gán vào request

    if (!user?.roles) {
      throw new ForbiddenException('No roles found');
    }

    const hasRole = user.roles.some((role: string) =>
      requiredRoles.includes(role),
    );

    if (!hasRole) {
      throw new ForbiddenException('Insufficient permissions');
    }

    return true;
  }
}
