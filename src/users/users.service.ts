import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './entities/user.entity';
import { Model } from 'mongoose';

// Type cho lean() query result
type UserLean = {
  _id: any;
  email: string;
  passwordHash: string;
  roles: string[];
  createdAt?: Date;
  updatedAt?: Date;
};

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  async findByEmail(email: string): Promise<UserLean | null> {
    return this.userModel.findOne({ email }).lean<UserLean>();
  }

  async create(
    email: string,
    passwordHash: string,
    roles: string[] = ['user'],
  ): Promise<UserDocument> {
    return this.userModel.create({ email, passwordHash, roles });
  }
}
