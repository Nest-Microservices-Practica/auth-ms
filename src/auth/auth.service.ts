import { Inject, Injectable, Logger } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { NATS_SERVICE } from '../config/services';
import { LoginUserDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(@Inject(NATS_SERVICE) private readonly client: ClientProxy) {}

  async registerUser(registerUserDto: RegisterUserDto) {
    return registerUserDto;
  }

  async loginUser(loginUserDto: LoginUserDto) {
    return loginUserDto;
  }

  async verifyToken() {
    return 'verify token';
  }
}
