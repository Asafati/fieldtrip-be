import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) { }

  async findByEmail(email: string): Promise<User | null> {
    const user = this.userRepository.findOne({ where: { email } });
    return user || null;
  }

  async findByEmailOrUsername(
    email: string,
    username: string,
  ): Promise<User | null> {
    const user = this.userRepository.findOne({
      where: [{ email }, { username }],
    });
    return user;
  }

  async findByResetToken(token: string): Promise<User | null> {
    const user = await this.userRepository.findOne({
      where: { resetPasswordToken: token },
    });
    return user || null;
  }

  async save(user: User): Promise<User> {
    return await this.userRepository.save(user);
  }


}
