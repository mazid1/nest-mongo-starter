import { Prop } from '@nestjs/mongoose';
import { Transform } from 'class-transformer';

export class BaseSchema {
  @Transform(({ value }) => value.toString())
  _id: string;

  @Prop()
  createdAt: Date;

  @Prop()
  updatedAt: Date;
}
