import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { JwtGuard } from './guard/jwt.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import type { JwtPayload } from './interfaces/jwt-payload.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/register')
  register(@Body() dto: RegisterAuthDto) {
    return this.authService.register(dto.email, dto.password);
  }

  @Post('/login')
  login(@Body() dto: LoginAuthDto) {
    return this.authService.login(dto.email, dto.password);
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
}
