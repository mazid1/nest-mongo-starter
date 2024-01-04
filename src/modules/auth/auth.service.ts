import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { UserDocument } from '../users/schemas/user.schema';
import { EnvVariables } from 'src/config/env-variables';
import { CreateUserDto } from '../users/dtos/createUser.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService<EnvVariables>,
  ) {}

  async signup(createUserDto: CreateUserDto) {
    const existingUser = await this.usersService.findOne({
      email: createUserDto.email,
    });
    if (existingUser) {
      throw new BadRequestException('Email already exists');
    }

    const passwordHash = await this.hashData(createUserDto.password);
    const newUser = await this.usersService.create({
      ...createUserDto,
      password: passwordHash,
    });
    return this.generateTokens(newUser);
  }

  async logout(userId: string) {
    await this.usersService.findOneAndUpdate(
      { _id: userId },
      { refreshToken: null },
    );
  }

  async validateUserCredentials(email: string, password: string) {
    const user = await this.usersService.findOne({ email });
    if (!user) return null;
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) return user;
    return null;
  }

  async generateTokens(user: UserDocument) {
    const accessToken = await this.getAccessToken(user);
    const refreshToken = await this.getRefreshToken(user);
    // update refresh token hash for better security
    await this.updateRefreshToken(user.id, refreshToken);
    return { accessToken, refreshToken };
  }

  private hashData(data: string) {
    return bcrypt.hash(data, this.configService.get('BCRYPT_SALT_ROUNDS'));
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

  private async updateRefreshToken(userId: string, refreshToken: string) {
    const refreshTokenHash = await this.hashData(refreshToken);
    return this.usersService.findOneAndUpdate(
      { _id: userId },
      { refreshToken: refreshTokenHash },
    );
  }
}
