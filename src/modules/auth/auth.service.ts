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
    if (user && user.passwordHash === password) {
      return user;
    }
    return null;
  }

  async getAccessToken(user: UserDocument) {
    const payload = { email: user.email, sub: user.id };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
      issuer: this.configService.get('JWT_ISSUER'),
      audience: this.configService.get('JWT_AUDIENCE'),
    });
    return {
      access_token: token,
    };
  }
}
