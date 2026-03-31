import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(
    private auth: AuthService,
    private jwt: JwtService,
  ) {}

  @Post('/register')
  register(@Body() dto: RegisterAuthDto) {
    return this.auth.register(dto.email, dto.password);
  }

  @Post('/login')
  login(@Body() dto: LoginAuthDto) {
    return this.auth.login(dto.email, dto.password);
  }

  @Get('/me')
  me(@Req() req: Request) {
    const headers = req.headers.authorization || '';
    const token = headers.startsWith('Bearer ') ? headers.slice(7) : '';
    const payload = this.jwt.verify(token);
    return { sub: payload.sub, email: payload.email, roles: payload.roles };
  }
}
