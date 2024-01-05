import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AccessTokenGuard } from '../auth/guards/accessToken.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { UserDocument } from './schemas/user.schema';

@ApiBearerAuth()
@ApiTags('users')
@Controller('users')
export class UsersController {
  @UseGuards(AccessTokenGuard)
  @Get('me')
  getCurrentUser(@Req() req: Request & { user: UserDocument }) {
    return req.user;
  }
}
