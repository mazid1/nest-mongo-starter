import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/localAuth.guard';
import { UserDocument } from '../users/schemas/user.schema';
import { RefreshTokenGuard } from './guards/refreshToken.guard';
import { CreateUserDto } from '../users/dtos/createUser.dto';
import { AccessTokenGuard } from './guards/accessToken.guard';
import { ApiBearerAuth, ApiBody, ApiHeader, ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dtos/login.dto';
import { TokensDto } from './dtos/tokens.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  signup(@Body() createUserDto: CreateUserDto): Promise<TokensDto> {
    return this.authService.signup(createUserDto);
  }

  @ApiBody({
    type: LoginDto,
  })
  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Req() req: Request & { user: UserDocument }): Promise<TokensDto> {
    return this.authService.generateTokens(req.user);
  }

  @ApiBearerAuth()
  @UseGuards(AccessTokenGuard)
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  logout(@Req() req: Request & { user: UserDocument }): Promise<void> {
    return this.authService.logout(req.user.id);
  }

  @ApiBearerAuth()
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer <refresh_token>',
  })
  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  refresh(@Req() req: Request & { user: UserDocument }): Promise<TokensDto> {
    return this.authService.generateTokens(req.user);
  }
}
