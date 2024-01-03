import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { LocalStrategy } from './strategies/local.strategy';
import { PassportModule } from '@nestjs/passport';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RefreshTokenGuard } from './guards/refreshToken.guard';
import { RefreshTokenStrategy } from './strategies/refreshToken.strategy';

@Module({
  imports: [UsersModule, JwtModule.register({}), PassportModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy,
    LocalAuthGuard,
    JwtStrategy,
    JwtAuthGuard,
    RefreshTokenStrategy,
    RefreshTokenGuard,
  ],
})
export class AuthModule {}
