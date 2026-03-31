import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async register(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);

    if (user) throw new ConflictException('User already exists');

    const passwordHash = await bcrypt.hash(password, 10);
    const userCreated = await this.usersService.create(email, passwordHash);

    return this.sign(userCreated._id.toString(), email, userCreated.roles);
  }
  async login(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);

    if (!user) throw new UnauthorizedException('Invalid email');

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid) throw new UnauthorizedException('Invalid credentials');

    return this.sign(user._id.toString(), email, user.roles);
  }

  private sign(sub: string, email: string, roles: string[]) {
    const access_token = this.jwtService.sign({ sub, email, roles });
    return {
      access_token,
      token_type: 'Bearer',
      expires_in: Number(process.env.JWT_EXPIRES_IN),
    };
  }
}
