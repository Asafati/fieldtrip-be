import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { User } from '../user/user.entity';
import { RegisterDTO } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { JwtPayloadDto } from './dto/jwt-payload.dto';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private userService: UserService,
  ) { }

  async signIn(email: string, password: string) {
    const user: User | null = await this.userService.findByEmail(email);
    if (
      user == null ||
      email != user.email ||
      !bcrypt.compareSync(password, user?.password_hash)
    ) {
      throw new UnauthorizedException();
    }
    const payload: JwtPayloadDto = { sub: user.id, email: user.email };
    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }

  async register(registerDto: RegisterDTO) {
    const existedUser: User | null =
      await this.userService.findByEmailOrUsername(
        registerDto.email,
        registerDto.username,
      );
    if (existedUser) {
      throw new HttpException(
        'Email or username already exists',
        HttpStatus.CONFLICT,
      );
    }
    const user: User = new User();
    user.email = registerDto.email;
    user.username = registerDto.username;
    user.password_hash = bcrypt.hashSync(registerDto.password, 10);

    user.profile_picture = '';
    user.bio = '';

    await this.userService.save(user);
  }

  async requestPasswordReset(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date();
    expiry.setHours(expiry.getHours() + 1); // 1 jam ke depan

    user.resetPasswordToken = token;
    user.resetPasswordExpires = expiry;
    await this.userService.save(user);

    // Ubah URL sesuai domain frontend kamu
    const resetLink = `https://fieldtrip-be.vercel.app/reset-password?token=${token}`;
    console.log(`Reset password link: ${resetLink}`); // nanti kirim via email di sini

    return { message: 'Reset link has been sent to email (simulasi).' };
  }
  // Simulasi kirim email
  // Simulasi reset password
  async resetPassword(token: string, newPassword: string) {
    const user: User | null = await this.userService.findByResetToken(token);


    if (
      !user ||
      !user.resetPasswordExpires ||
      user.resetPasswordExpires < new Date()
    ) {
      throw new HttpException('Invalid or expired token', HttpStatus.BAD_REQUEST);
    }

    user.password_hash = bcrypt.hashSync(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await this.userService.save(user);

    return { message: 'Password successfully reset.' };
  }


}
