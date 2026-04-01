import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Headers,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { JwtGuard } from './guard/jwt.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import type { JwtPayload } from './interfaces/jwt-payload.interface';
import type { AuthResponse } from './interfaces/auth-response.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/register')
  register(@Body() dto: RegisterAuthDto): Promise<AuthResponse> {
    return this.authService.register(dto.email, dto.password);
  }

  @Post('/login')
  login(@Body() dto: LoginAuthDto): Promise<AuthResponse> {
    return this.authService.login(dto.email, dto.password);
  }

  @Post('/introspect')
  async introspect(
    @Headers('authorization') authHeader?: string,
    @Headers('x-internal-api-key') internalApiKey?: string,
  ) {
    this.assertInternalApiKey(internalApiKey);

    const token = this.extractBearerToken(authHeader);
    if (!token) {
      throw new UnauthorizedException('Token not found');
    }

    const user = await this.authService.introspect(token);
    return {
      active: true,
      user,
    };
  }

  @Get('/me')
  @UseGuards(JwtGuard)
  me(@CurrentUser() user: JwtPayload) {
    return {
      sub: user.sub,
      email: user.email,
      roles: user.roles,
    };
  }

  private assertInternalApiKey(actualKey?: string): void {
    const expectedKey = process.env.AUTH_INTERNAL_API_KEY;
    if (!expectedKey) {
      throw new ForbiddenException('AUTH_INTERNAL_API_KEY is not configured');
    }

    if (!actualKey || actualKey !== expectedKey) {
      throw new ForbiddenException('Invalid internal API key');
    }
  }

  private extractBearerToken(authHeader?: string): string | undefined {
    if (!authHeader) return undefined;
    const [type, token] = authHeader.split(' ');
    return type === 'Bearer' ? token : undefined;
  }
}
