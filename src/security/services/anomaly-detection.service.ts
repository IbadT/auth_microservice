/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */

/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/require-await */
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma.service';
import { SecurityLoggerService } from '../security-logger.service';
import { createClient, RedisClientType } from 'redis';

interface UserBehavior {
  userId: string;
  ipAddress: string;
  userAgent: string;
  action: string;
  timestamp: Date;
  success: boolean;
}

interface AnomalyScore {
  score: number;
  factors: string[];
  threshold: number;
}

@Injectable()
export class AnomalyDetectionService {
  private redisClient: RedisClientType;
  private readonly anomalyThreshold: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
    private readonly securityLogger: SecurityLoggerService,
  ) {
    this.anomalyThreshold = this.configService.get('ANOMALY_THRESHOLD', 0.7);
    void this.initRedis();
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
      this.securityLogger.logRedisEvent('CONNECTED', 'AnomalyDetectionService connected to Redis');
    } catch (error) {
      this.securityLogger.logSecurityError('REDIS_CONNECTION_FAILED', error.message);
      // В продакшене можно использовать fallback или перезапуск
    }
  }

  // Анализ поведения пользователя
  async analyzeUserBehavior(
    userId: string,
    behavior: UserBehavior,
  ): Promise<AnomalyScore> {
    const factors: string[] = [];
    let score = 0;

    // 1. Анализ IP адреса
    const ipScore = await this.analyzeIPAddress(userId, behavior.ipAddress);
    score += ipScore.score;
    if (ipScore.factors.length > 0) {
      factors.push(...ipScore.factors);
    }

    // 2. Анализ User-Agent
    const uaScore = await this.analyzeUserAgent(userId, behavior.userAgent);
    score += uaScore.score;
    if (uaScore.factors.length > 0) {
      factors.push(...uaScore.factors);
    }

    // 3. Анализ времени активности
    const timeScore = await this.analyzeTimePattern(userId, behavior.timestamp);
    score += timeScore.score;
    if (timeScore.factors.length > 0) {
      factors.push(...timeScore.factors);
    }

    // 4. Анализ частоты действий
    const frequencyScore = await this.analyzeActionFrequency(
      userId,
      behavior.action,
    );
    score += frequencyScore.score;
    if (frequencyScore.factors.length > 0) {
      factors.push(...frequencyScore.factors);
    }

    // 5. Анализ успешности действий
    const successScore = await this.analyzeSuccessRate(
      userId,
      behavior.success,
    );
    score += successScore.score;
    if (successScore.factors.length > 0) {
      factors.push(...successScore.factors);
    }

    // Нормализуем score до 0-1
    const normalizedScore = Math.min(score / 5, 1);

    const result: AnomalyScore = {
      score: normalizedScore,
      factors,
      threshold: this.anomalyThreshold,
    };

    // Логируем аномалию если превышен порог
    if (normalizedScore > this.anomalyThreshold) {
      this.securityLogger.logSecurityError(
        'ANOMALY_DETECTED',
        `User: ${userId}, Score: ${normalizedScore.toFixed(2)}, Factors: ${factors.join(', ')}`,
      );
    }

    return result;
  }

  // Анализ IP адреса
  private async analyzeIPAddress(
    userId: string,
    ipAddress: string,
  ): Promise<{ score: number; factors: string[] }> {
    const factors: string[] = [];
    let score = 0;

    // Получаем историю IP адресов пользователя
    const userIPs = await this.prismaService.loginAttempt.findMany({
      where: { userId },
      select: { ipAddress: true },
      distinct: ['ipAddress'],
      orderBy: { timestamp: 'desc' },
      take: 10,
    });

    const knownIPs = userIPs.map((attempt) => attempt.ipAddress);

    // Новый IP адрес
    if (!knownIPs.includes(ipAddress)) {
      score += 0.3;
      factors.push('new_ip_address');
    }

    // Проверяем геолокацию (можно интегрировать с внешним API)
    const isSuspiciousLocation = await this.checkSuspiciousLocation(ipAddress);
    if (isSuspiciousLocation) {
      score += 0.4;
      factors.push('suspicious_location');
    }

    return { score, factors };
  }

  // Анализ User-Agent
  private async analyzeUserAgent(
    userId: string,
    userAgent: string,
  ): Promise<{ score: number; factors: string[] }> {
    const factors: string[] = [];
    let score = 0;

    // Получаем историю User-Agent пользователя
    const userUAs = await this.prismaService.loginAttempt.findMany({
      where: { userId },
      select: { userAgent: true },
      distinct: ['userAgent'],
      orderBy: { timestamp: 'desc' },
      take: 5,
    });

    const knownUAs = userUAs.map((attempt) => attempt.userAgent);

    // Новый User-Agent
    if (!knownUAs.includes(userAgent)) {
      score += 0.2;
      factors.push('new_user_agent');
    }

    // Подозрительные User-Agent
    const suspiciousPatterns = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
    ];

    if (suspiciousPatterns.some((pattern) => pattern.test(userAgent))) {
      score += 0.5;
      factors.push('suspicious_user_agent');
    }

    return { score, factors };
  }

  // Анализ временных паттернов
  private async analyzeTimePattern(
    userId: string,
    timestamp: Date,
  ): Promise<{ score: number; factors: string[] }> {
    const factors: string[] = [];
    let score = 0;

    const hour = timestamp.getHours();

    // Активность в необычное время (2-6 утра)
    if (hour >= 2 && hour <= 6) {
      score += 0.3;
      factors.push('unusual_time');
    }

    // Получаем историю активности пользователя
    const recentActivity = await this.prismaService.loginAttempt.findMany({
      where: { userId },
      orderBy: { timestamp: 'desc' },
      take: 10,
    });

    // Слишком частые попытки
    if (recentActivity && recentActivity.length >= 5) {
      const timeSpan =
        recentActivity[0].timestamp.getTime() -
        recentActivity[4].timestamp.getTime();
      const minutesSpan = timeSpan / (1000 * 60);

      if (minutesSpan < 5) {
        // 5 попыток за 5 минут
        score += 0.4;
        factors.push('high_frequency');
      }
    }

    return { score, factors };
  }

  // Анализ частоты действий
  private async analyzeActionFrequency(
    userId: string,
    action: string,
  ): Promise<{ score: number; factors: string[] }> {
    const factors: string[] = [];
    let score = 0;

    const key = `action_freq:${userId}:${action}`;
    const count = await this.redisClient.incr(key);
    await this.redisClient.expire(key, 3600); // 1 час

    // Слишком много действий за короткое время
    if (count > 50) {
      score += 0.3;
      factors.push('excessive_actions');
    }

    return { score, factors };
  }

  // Анализ успешности действий
  private async analyzeSuccessRate(
    userId: string,
    success: boolean,
  ): Promise<{ score: number; factors: string[] }> {
    const factors: string[] = [];
    let score = 0;

    const key = `success_rate:${userId}`;
    const totalKey = `${key}:total`;
    const successKey = `${key}:success`;

    await this.redisClient.incr(totalKey);
    if (success) {
      await this.redisClient.incr(successKey);
    }

    await this.redisClient.expire(totalKey, 3600);
    await this.redisClient.expire(successKey, 3600);

    const total = await this.redisClient.get(totalKey);
    const successCount = await this.redisClient.get(successKey);

    if (total && successCount) {
      const successRate = parseInt(successCount) / parseInt(total);

      // Низкий процент успешности
      if (successRate < 0.3) {
        score += 0.4;
        factors.push('low_success_rate');
      }
    }

    return { score, factors };
  }

  // Проверка подозрительной локации (заглушка)
  private async checkSuspiciousLocation(ipAddress: string): Promise<boolean> {
    // Здесь можно интегрировать с сервисами геолокации
    // Например: MaxMind, IP2Location, etc.
    const suspiciousRanges = [
      '192.168.1.0/24', // Локальная сеть
      '10.0.0.0/8', // Приватная сеть
    ];

    // Простая проверка для демонстрации
    return suspiciousRanges.some((range) => {
      const [network, mask] = range.split('/');
      return ipAddress.startsWith(network.split('.').slice(0, -1).join('.'));
    });
  }

  // Получение статистики аномалий
  async getAnomalyStats(userId: string): Promise<{
    totalEvents: number;
    anomalyEvents: number;
    averageScore: number;
    lastAnomaly: Date | null;
  }> {
    // const events = await this.prismaService.loginAttempts.findMany({
    const events = await this.prismaService.loginAttempt.findMany({
      where: { userId },
      orderBy: { timestamp: 'desc' },
      take: 100,
    });

    const totalEvents = events.length;
    const anomalyEvents = events.filter((e) =>
      e.failureReason?.includes('anomaly'),
    ).length;
    const averageScore = totalEvents > 0 ? anomalyEvents / totalEvents : 0;
    const lastAnomaly =
      events.find((e) => e.failureReason?.includes('anomaly'))?.timestamp ||
      null;

    return {
      totalEvents,
      anomalyEvents,
      averageScore,
      lastAnomaly,
    };
  }
}
