import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private jwt: JwtService,
  ) {}

  canActivate(ctx: ExecutionContext): boolean {
    const roles = this.reflector.get<string[]>('roles', ctx.getHandler());
    if (!roles?.length) return true;

    const req = ctx.switchToHttp().getRequest();
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const payload = this.jwt.verify(token);
    const ok = payload.roles?.some((r: string) => roles.includes(r));

    if (!ok) throw new ForbiddenException('Insufficient role');
    return true;
  }
}
