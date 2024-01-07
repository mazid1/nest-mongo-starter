import {
  Controller,
  Get,
  Req,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { AccessTokenGuard } from '../auth/guards/accessToken.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { User, UserDocument } from './schemas/user.schema';
import { mongooseClassSerializerInterceptor } from 'src/interceptors/mongooseClassSerializer.interceptor';

@ApiBearerAuth()
@ApiTags('users')
@Controller('users')
export class UsersController {
  @UseInterceptors(mongooseClassSerializerInterceptor(User))
  @UseGuards(AccessTokenGuard)
  @Get('me')
  getCurrentUser(@Req() req: Request & { user: UserDocument }): User {
    return req.user;
  }
}
