import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { BaseSchema } from 'src/core/base.schema';

export type UserSessionDocument = HydratedDocument<UserSession>;

@Schema({ timestamps: true, versionKey: false })
export class UserSession extends BaseSchema {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true, unique: true })
  accessToken: string;

  @Prop({ required: true, unique: true })
  refreshToken: string;

  @Prop({ required: true, expires: 0 })
  expiresAt: Date;
}

export const UserSessionSchema = SchemaFactory.createForClass(UserSession);
