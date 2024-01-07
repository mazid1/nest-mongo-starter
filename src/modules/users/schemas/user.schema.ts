import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { ApiHideProperty } from '@nestjs/swagger';
import { Exclude } from 'class-transformer';
import { HydratedDocument } from 'mongoose';
import { BaseSchema } from 'src/core/base.schema';

export type UserDocument = HydratedDocument<User>;

@Schema({ timestamps: true, versionKey: false })
export class User extends BaseSchema {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, unique: true })
  email: string;

  @ApiHideProperty()
  @Exclude()
  @Prop({ required: true })
  password: string; // hashed password

  @ApiHideProperty()
  @Exclude()
  @Prop({ nullable: true })
  refreshToken?: string; // hashed refresh token
}

export const UserSchema = SchemaFactory.createForClass(User);
