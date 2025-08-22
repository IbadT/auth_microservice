import { Injectable } from '@nestjs/common';
import {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
} from './src/auth/auth';
import { PrismaService } from '../prisma.service';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { status } from '@grpc/grpc-js';

interface GrpcError {
  code: number;
  message: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  async login(data: LoginRequest): Promise<LoginResponse> {
    const { email, password } = data;

    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      const error: GrpcError = {
        code: status.NOT_FOUND,
        message: 'User not found',
      };
      throw new RpcException(error);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      const error: GrpcError = {
        code: status.PERMISSION_DENIED,
        message: 'Invalid password',
      };
      throw new RpcException(error);
    }

    const { accessToken, refreshToken } = await this.generateTokens(
      user.id,
      user.email,
    );
    return {
      accessToken,
      refreshToken,
    };
  }

  async register(data: RegisterRequest): Promise<RegisterResponse> {
    const { email, password } = data;

    const existingUser = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (existingUser) {
      const error: GrpcError = {
        code: status.ALREADY_EXISTS,
        message: 'User already exists',
      };
      throw new RpcException(error);
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await this.prismaService.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    const { accessToken, refreshToken } = await this.generateTokens(
      newUser.id,
      newUser.email,
    );
    return {
      accessToken,
      refreshToken,
    };
  }

  async generateTokens(
    userId: string,
    email: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: this.configService.getOrThrow<string>('JWT_EXPIRES_IN'),
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: this.configService.getOrThrow<string>('JWT_REFRESH_IN'),
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.getOrThrow<string>('JWT_SUPER_SECRET_WORD'),
      });

      const user = await this.prismaService.user.findUnique({
        where: {
          id: payload.sub,
        },
      });

      if (!user) {
        const error: GrpcError = {
          code: status.NOT_FOUND,
          message: 'User not found',
        };
        throw new RpcException(error);
      }

      return await this.generateTokens(user.id, user.email);
    } catch {
      const error: GrpcError = {
        code: status.PERMISSION_DENIED,
        message: 'Invalid refresh token',
      };
      throw new RpcException(error);
    }
  }
}
