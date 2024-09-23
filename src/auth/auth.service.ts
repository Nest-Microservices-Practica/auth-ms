import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { NATS_SERVICE } from '../config/services';
import { LoginUserDto, RegisterUserDto } from './dto';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from '../config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @Inject(NATS_SERVICE) private readonly client: ClientProxy,
    private readonly jwtService: JwtService,
  ) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    try {
      const { email, name, password } = registerUserDto;

      const user = await this.user.findUnique({
        where: { email },
      });

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email,
          name,
          password: bcrypt.hashSync(password, 10),
        },
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: __, ...userWithoutPassword } = newUser;

      return {
        user: userWithoutPassword,
        token: await this.signJWT(userWithoutPassword),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    try {
      const { email, password } = loginUserDto;

      const user = await this.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'Invalid credentials',
        });
      }

      const isPasswordCorrect = bcrypt.compareSync(password, user.password);

      if (!isPasswordCorrect) {
        throw new RpcException({
          status: 400,
          message: 'Invalid credentials',
        });
      }

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: __, ...userWithoutPassword } = user;

      return {
        user: userWithoutPassword,
        token: await this.signJWT(userWithoutPassword),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
  }
}
