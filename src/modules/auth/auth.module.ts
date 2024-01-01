import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { LocalStrategy } from './strategies/local.strategy';
import { PassportModule } from '@nestjs/passport';
import { LocalAuthGuard } from './guards/local-auth.guard';

@Module({
  imports: [UsersModule, JwtModule.register({ global: true }), PassportModule],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, LocalAuthGuard],
})
export class AuthModule {}
