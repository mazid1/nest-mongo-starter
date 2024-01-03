import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AccessTokenGuard } from '../auth/guards/accessToken.guard';

@Controller('users')
export class UsersController {
  @UseGuards(AccessTokenGuard)
  @Get('me')
  getCurrentUser(@Req() req: Request & { user: any }) {
    return req.user;
  }
}
