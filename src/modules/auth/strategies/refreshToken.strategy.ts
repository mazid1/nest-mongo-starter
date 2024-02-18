import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt } from 'passport-jwt';
import { Strategy } from 'passport-jwt';
import { EnvVariables } from 'src/config/env-variables';
import { UsersService } from 'src/modules/users/users.service';
import { AuthService } from '../auth.service';
import { JWTPayload } from './type';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    private usersService: UsersService,
    private authService: AuthService,
    private configService: ConfigService<EnvVariables>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_REFRESH_TOKEN_SECRET'),
      issuer: configService.get('JWT_ISSUER'),
      audience: configService.get('JWT_AUDIENCE'),
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: JWTPayload) {
    const refreshToken = req.get('Authorization').split(' ').pop();
    const session = await this.authService.findOneUserSession({
      refreshToken,
    });
    if (!session) return null;

    const user = await this.usersService.findOne({
      _id: payload.sub,
    });
    return user;
  }
}
