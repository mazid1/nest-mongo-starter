import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

  async login(email: string, pass: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (user?.passwordHash !== pass) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
