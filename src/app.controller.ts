import { Controller, Get, VERSION_NEUTRAL } from '@nestjs/common';

@Controller({
  version: VERSION_NEUTRAL,
})
export class AppController {
  constructor() {}

  @Get('/health')
  getHealth(): string {
    return 'OK';
  }
}
