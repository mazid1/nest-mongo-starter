import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { UserDocument } from '../users/schemas/user.schema';
import { ConfigService } from '@nestjs/config';
import { EnvVariables } from 'src/config/env-variables';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService<EnvVariables>,
  ) {}

  async validateUserCredentials(email: string, password: string) {
    const user = await this.usersService.findOne({ email });
    // todo: use bcrypt
    const passwordHash = password;
    if (user && user.passwordHash === passwordHash) {
      return user;
    }
    return null;
  }

  async getTokens(user: UserDocument) {
    const accessToken = await this.getAccessToken(user);
    const refreshToken = await this.getRefreshToken(user);
    // update refresh token hash for better security
    await this.updateRefreshToken(user.id, refreshToken);
    return { accessToken, refreshToken };
  }

  private async getAccessToken(user: UserDocument) {
    const payload = { email: user.email, sub: user.id };
    const token = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
      issuer: this.configService.get('JWT_ISSUER'),
      audience: this.configService.get('JWT_AUDIENCE'),
    });
    return token;
  }

  private async getRefreshToken(user: UserDocument) {
    const payload = { email: user.email, sub: user.id };
    const token = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_TOKEN_EXPIRATION_TIME'),
      issuer: this.configService.get('JWT_ISSUER'),
      audience: this.configService.get('JWT_AUDIENCE'),
    });
    return token;
  }

  private updateRefreshToken(userId: string, refreshToken: string) {
    // todo: use bcrypt
    const refreshTokenHash = refreshToken;
    return this.usersService.findOneAndUpdate(
      { _id: userId },
      { refreshTokenHash },
    );
  }
}
