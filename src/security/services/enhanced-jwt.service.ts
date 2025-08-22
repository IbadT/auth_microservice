/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-misused-promises */
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { createClient, RedisClientType } from 'redis';
import { randomUUID } from 'crypto';
import { SecurityLoggerService } from '../security-logger.service';

interface JwtPayload {
  sub: string;
  email: string;
  jti: string; // JWT ID для отзыва токенов
  iat: number;
  exp: number;
  type: 'access' | 'refresh';
}

@Injectable()
export class EnhancedJwtService {
  private redisClient: RedisClientType;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly securityLogger: SecurityLoggerService,
  ) {
    this.initRedis();
  }

  private async initRedis() {
    const redisConfig: any = {
      socket: {
        host: this.configService.get('REDIS_HOST', 'redis'),
        port: this.configService.get('REDIS_PORT', 6379),
      },
    };

    // Добавляем аутентификацию если указана
    const password = this.configService.get('REDIS_PASSWORD');
    const username = this.configService.get('REDIS_USERNAME');
    
    if (password) {
      redisConfig.password = password;
    }
    if (username) {
      redisConfig.username = username;
    }

    this.redisClient = createClient(redisConfig);
    
    try {
      await this.redisClient.connect();
      this.securityLogger.logRedisEvent('CONNECTED', 'EnhancedJwtService connected to Redis');
    } catch (error) {
      this.securityLogger.logSecurityError('REDIS_CONNECTION_FAILED', error.message);
      // В продакшене можно использовать fallback или перезапуск
    }
  }

  // Генерация токенов с JTI
  async generateTokens(
    userId: string,
    email: string,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    accessTokenId: string;
    refreshTokenId: string;
  }> {
    const accessTokenId = randomUUID();
    const refreshTokenId = randomUUID();

    const accessPayload: JwtPayload = {
      sub: userId,
      email,
      jti: accessTokenId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 15 * 60, // 15 минут
      type: 'access',
    };

    const refreshPayload: JwtPayload = {
      sub: userId,
      email,
      jti: refreshTokenId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 дней
      type: 'refresh',
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(accessPayload),
      this.jwtService.signAsync(refreshPayload),
    ]);

    // Сохраняем метаданные токенов в Redis
    await Promise.all([
      this.storeTokenMetadata(accessTokenId, userId, 'access', 15 * 60),
      this.storeTokenMetadata(
        refreshTokenId,
        userId,
        'refresh',
        7 * 24 * 60 * 60,
      ),
    ]);

    this.securityLogger.logJwtEvent(
      'tokens_generated',
      `User: ${userId}, Access JTI: ${accessTokenId}`,
    );

    return {
      accessToken,
      refreshToken,
      accessTokenId,
      refreshTokenId,
    };
  }

  // Верификация токена с проверкой отзыва
  async verifyToken(token: string): Promise<JwtPayload> {
    try {
      const payload = await this.jwtService.verifyAsync(token);

      // Проверяем, не отозван ли токен
      const isRevoked = await this.isTokenRevoked(payload.jti);
      if (isRevoked) {
        throw new Error('Token has been revoked');
      }

      return payload;
    } catch (error) {
      this.securityLogger.logJwtEvent(
        'token_verification_failed',
        `Error: ${error.message}`,
      );
      throw error;
    }
  }

  // Отзыв токена по JTI
  async revokeToken(jti: string): Promise<void> {
    await this.redisClient.setEx(`revoked:${jti}`, 7 * 24 * 60 * 60, '1');
    this.securityLogger.logJwtEvent('token_revoked', `JTI: ${jti}`);
  }

  // Отзыв всех токенов пользователя
  async revokeAllUserTokens(userId: string): Promise<void> {
    const pattern = `token_meta:*:${userId}`;
    const keys = await this.redisClient.keys(pattern);

    const revokePromises = keys.map(async (key) => {
      const jti = key.split(':')[1];
      await this.revokeToken(jti);
    });

    await Promise.all(revokePromises);
    this.securityLogger.logJwtEvent(
      'all_user_tokens_revoked',
      `User: ${userId}`,
    );
  }

  // Проверка отзыва токена
  private async isTokenRevoked(jti: string): Promise<boolean> {
    const result = await this.redisClient.get(`revoked:${jti}`);
    return result !== null;
  }

  // Сохранение метаданных токена
  private async storeTokenMetadata(
    jti: string,
    userId: string,
    type: 'access' | 'refresh',
    ttl: number,
  ): Promise<void> {
    const metadata = {
      userId,
      type,
      issuedAt: Date.now(),
      expiresAt: Date.now() + ttl * 1000,
    };

    await this.redisClient.setEx(
      `token_meta:${jti}:${userId}`,
      ttl,
      JSON.stringify(metadata),
    );
  }

  // Получение активных токенов пользователя
  async getUserActiveTokens(userId: string): Promise<
    Array<{
      jti: string;
      type: string;
      issuedAt: number;
      expiresAt: number;
    }>
  > {
    const pattern = `token_meta:*:${userId}`;
    const keys = await this.redisClient.keys(pattern);

    const tokens = await Promise.all(
      keys.map(async (key) => {
        const metadata = await this.redisClient.get(key);
        const jti = key.split(':')[1];

        return {
          jti,
          ...JSON.parse(metadata || '{}'),
        };
      }),
    );

    return tokens.filter((token) => !this.isTokenRevoked(token.jti));
  }
}
