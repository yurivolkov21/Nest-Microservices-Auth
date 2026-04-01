import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { AuthResponse } from './interfaces/auth-response.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async register(email: string, password: string): Promise<AuthResponse> {
    const user = await this.usersService.findByEmail(email);

    if (user) throw new ConflictException('User already exists');

    const passwordHash = await bcrypt.hash(password, 10);
    const userCreated = await this.usersService.create(email, passwordHash);

    return this.sign(userCreated._id.toString(), email, userCreated.roles);
  }

  async login(email: string, password: string): Promise<AuthResponse> {
    const user = await this.usersService.findByEmail(email);

    if (!user) throw new UnauthorizedException('Invalid email');

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid credentials');

    return this.sign(user._id.toString(), email, user.roles);
  }

  async introspect(token: string): Promise<JwtPayload> {
    if (!token) {
      throw new BadRequestException('Token is required');
    }

    try {
      return await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: process.env.JWT_SECRET,
        ...(process.env.JWT_ISSUER ? { issuer: process.env.JWT_ISSUER } : {}),
        ...(process.env.JWT_AUDIENCE
          ? { audience: process.env.JWT_AUDIENCE }
          : {}),
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  private sign(sub: string, email: string, roles: string[]): AuthResponse {
    const payload: JwtPayload = { sub, email, roles };
    const access_token = this.jwtService.sign(payload);

    const expiresIn = parseInt(process.env.JWT_EXPIRES ?? '86400', 10);

    return {
      access_token,
      token_type: 'Bearer',
      expires_in: expiresIn,
    };
  }
}
