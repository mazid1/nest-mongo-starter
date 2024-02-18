import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { UserDocument } from '../users/schemas/user.schema';
import { EnvVariables } from 'src/config/env-variables';
import { CreateUserDto } from '../users/dtos/createUser.dto';
import * as bcrypt from 'bcrypt';
import { createHash } from 'crypto';
import { FilterQuery, Model } from 'mongoose';
import { UserSession } from './schemas/user-session.schema';
import { InjectModel } from '@nestjs/mongoose';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService<EnvVariables>,
    @InjectModel(UserSession.name) private userSessionModel: Model<UserSession>,
  ) {}

  async signup(createUserDto: CreateUserDto) {
    const existingUser = await this.usersService.findOne({
      email: createUserDto.email,
    });
    if (existingUser) {
      throw new BadRequestException('Email already exists');
    }

    const passwordHash = await this.hashPassword(createUserDto.password);
    const newUser = await this.usersService.create({
      ...createUserDto,
      password: passwordHash,
    });

    return this.login(newUser);
  }

  async login(user: UserDocument) {
    const tokens = await this.generateTokens(user);

    const refreshTokenData = this.jwtService.decode(tokens.refreshToken);

    await this.userSessionModel.create({
      userId: user.id,
      accessToken: this.hashToken(tokens.accessToken),
      refreshToken: this.hashToken(tokens.refreshToken),
      expiresAt: new Date(refreshTokenData.exp * 1000),
    });

    return tokens;
  }

  async logout(accessToken: string) {
    await this.userSessionModel.findOneAndDelete({
      accessToken: this.hashToken(accessToken),
    });
  }

  async logoutFromAllDevices(accessToken: string) {
    const { userId } = await this.findOneUserSession({ accessToken });
    await this.userSessionModel.deleteMany({ userId });
  }

  async refreshUserSession(user: UserDocument, refreshToken: string) {
    const userSession = await this.findOneUserSession({
      refreshToken,
    });
    if (!userSession) throw new UnauthorizedException();

    const tokens = await this.generateTokens(user);

    await userSession
      .updateOne({
        accessToken: this.hashToken(tokens.accessToken),
        refreshToken: this.hashToken(tokens.refreshToken),
        expiresAt: new Date(
          this.jwtService.decode(tokens.refreshToken).exp * 1000,
        ),
      })
      .exec();

    return tokens;
  }

  async validateUserCredentials(email: string, password: string) {
    const user = await this.usersService.findOne({ email });
    if (!user) return null;
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) return user;
    return null;
  }

  findOneUserSession(query: FilterQuery<UserSession>) {
    return this.userSessionModel
      .findOne({
        ...query,
        ...(query.accessToken && {
          accessToken: this.hashToken(query.accessToken),
        }),
        ...(query.refreshToken && {
          refreshToken: this.hashToken(query.refreshToken),
        }),
      })
      .exec();
  }

  private async generateTokens(user: UserDocument) {
    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);
    return { accessToken, refreshToken };
  }

  private hashPassword(data: string) {
    return bcrypt.hash(data, this.configService.get('BCRYPT_SALT_ROUNDS'));
  }

  private hashToken(data: string) {
    return createHash('sha256').update(data).digest('base64');
  }

  private async generateAccessToken(user: UserDocument) {
    const payload = { email: user.email, sub: user.id };
    const token = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
      issuer: this.configService.get('JWT_ISSUER'),
      audience: this.configService.get('JWT_AUDIENCE'),
    });
    return token;
  }

  private async generateRefreshToken(user: UserDocument) {
    const payload = { email: user.email, sub: user.id };
    const token = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_TOKEN_EXPIRATION_TIME'),
      issuer: this.configService.get('JWT_ISSUER'),
      audience: this.configService.get('JWT_AUDIENCE'),
    });
    return token;
  }
}
