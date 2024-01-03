import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './schemas/user.schema';
import { FilterQuery, Model } from 'mongoose';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  findOne(query: FilterQuery<User>): Promise<UserDocument> {
    return this.userModel.findOne(query).exec();
  }

  findOneAndUpdate(
    query: FilterQuery<User>,
    update: Partial<User>,
  ): Promise<UserDocument> {
    return this.userModel.findOneAndUpdate(query, update, { new: true }).exec();
  }
}
