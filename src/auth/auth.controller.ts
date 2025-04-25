import { Body, Controller, Post } from '@nestjs/common';
import { LoginDTO } from './dto/login.dto';
import { RegisterDTO } from './dto/register.dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('login')
  signIn(@Body() signInDto: LoginDTO) {
    return this.authService.signIn(signInDto.email, signInDto.password);
  }

  @Post('register')
  register(@Body() registerDto: RegisterDTO) {
    return this.authService.register(registerDto);
  }
}
