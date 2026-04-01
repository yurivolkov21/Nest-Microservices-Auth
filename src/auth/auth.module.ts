import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    UsersModule,
    ConfigModule,
    JwtModule.registerAsync({
      global: true,
      useFactory: () => {
        const secret = process.env.JWT_SECRET;
        const expiresIn = parseInt(process.env.JWT_EXPIRES ?? '86400', 10);
        const issuer = process.env.JWT_ISSUER;
        const audience = process.env.JWT_AUDIENCE;

        if (!secret) {
          throw new Error('JWT_SECRET environment variable is not defined');
        }

        if (isNaN(expiresIn) || expiresIn <= 0) {
          throw new Error(
            'JWT_EXPIRES must be a valid positive number (in seconds)',
          );
        }

        return {
          secret,
          signOptions: {
            expiresIn,
            ...(issuer ? { issuer } : {}),
            ...(audience ? { audience } : {}),
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [JwtModule],
})
export class AuthModule {}
