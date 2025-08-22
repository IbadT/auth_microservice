import { Injectable } from '@nestjs/common';
import { createClient, RedisClientType } from 'redis';
import { ConfigService } from '@nestjs/config';
import { SecurityLoggerService } from '../security-logger.service';

@Injectable()
export class BruteForceService {
  private redisClient: RedisClientType;

  constructor(
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
      this.securityLogger.logRedisEvent('CONNECTED', 'BruteForceService connected to Redis');
    } catch (error) {
      this.securityLogger.logSecurityError('REDIS_CONNECTION_FAILED', error.message);
      // В продакшене можно использовать fallback или перезапуск
    }
  }

  // Проверка заблокирован ли IP или email
  async isBlocked(key: string): Promise<boolean> {
    const attempts = await this.redisClient.get(`bf:${key}`);
    return attempts !== null && parseInt(attempts) >= 5;
  }

  // Увеличение счетчика неудачных попыток
  async recordFailedAttempt(key: string): Promise<void> {
    const current = await this.redisClient.incr(`bf:${key}`);
    await this.redisClient.expire(`bf:${key}`, 900); // 15 минут

    if (current === 5) {
      this.securityLogger.logSecurityError(
        'BRUTE_FORCE_DETECTED',
        `Key: ${key}`,
      );
    }
  }

  // Очистка счетчика при успешной аутентификации
  async clearFailedAttempts(key: string): Promise<void> {
    await this.redisClient.del(`bf:${key}`);
  }

  // Получение времени до разблокировки
  async getBlockTimeRemaining(key: string): Promise<number> {
    return await this.redisClient.ttl(`bf:${key}`);
  }
}
