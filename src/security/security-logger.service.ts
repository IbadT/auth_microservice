import { Injectable, Logger } from '@nestjs/common';


@Injectable()
export class SecurityLoggerService {
  private readonly logger = new Logger(SecurityLoggerService.name);

  // Логирование подозрительной активности
  logSuspiciousActivity(
    ip: string,
    method: string,
    url: string,
    reason: string,
  ): void {
    this.logger.warn(
      `🚨 [SECURITY] SUSPICIOUS_ACTIVITY detected from IP: ${ip} | Method: ${method} | URL: ${url} | Reason: ${reason}`,
    );
  }

  // Логирование успешных запросов
  logSuccess(ip: string, method: string, url: string): void {
    this.logger.log(
      `✅ [SECURITY] SUCCESS request from IP: ${ip} | Method: ${method} | URL: ${url}`,
    );
  }

  // Логирование ошибок
  logError(ip: string, method: string, url: string, error: string): void {
    this.logger.error(
      `❌ [SECURITY] ERROR request from IP: ${ip} | Method: ${method} | Error: ${error}`,
    );
  }

  // Логирование превышения лимитов
  logRateLimitExceeded(ip: string): void {
    this.logger.warn(
      `⚠️ [SECURITY] RATE_LIMIT_EXCEEDED for IP: ${ip}`,
    );
  }

  // Логирование блокировки IP
  logIpBlocked(ip: string, reason: string): void {
    this.logger.warn(
      `🚫 [SECURITY] IP_BLOCKED | IP: ${ip} | Reason: ${reason}`,
    );
  }

  // Логирование добавления в черный список
  logIpBlacklisted(ip: string): void {
    this.logger.warn(
      `🚫 [SECURITY] IP_BLACKLISTED | IP: ${ip}`,
    );
  }

  // Логирование удаления из черного списка
  logIpWhitelisted(ip: string): void {
    this.logger.log(
      `✅ [SECURITY] IP_WHITELISTED | IP: ${ip}`,
    );
  }

  // Логирование ошибок безопасности
  logSecurityError(error: string, details?: string): void {
    this.logger.error(
      `💥 [SECURITY] SECURITY_ERROR | Error: ${error}` +
        (details ? ` | Details: ${details}` : ''),
    );
  }

  // Логирование аутентификации
  logAuthAttempt(ip: string, email: string, success: boolean): void {
    const icon = success ? '🔐' : '🔓';
    const status = success ? 'SUCCESS' : 'FAILED';

    this.logger.log(
      `${icon} [AUTH] ${status} login attempt from IP: ${ip} for email: ${email}`,
    );
  }

  // Логирование регистрации
  logRegistration(ip: string, email: string, success: boolean): void {
    const icon = success ? '📝' : '❌';
    const status = success ? 'SUCCESS' : 'FAILED';

    this.logger.log(
      `${icon} [AUTH] ${status} registration from IP: ${ip} for email: ${email}`,
    );
  }

  // Логирование обновления токенов
  logTokenRefresh(ip: string, success: boolean): void {
    const icon = success ? '🔄' : '❌';
    const status = success ? 'SUCCESS' : 'FAILED';

    this.logger.log(
      `${icon} [AUTH] ${status} token refresh from IP: ${ip}`,
    );
  }

  // Логирование JWT событий
  logJwtEvent(event: string, details: string): void {
    this.logger.log(
      `🔑 [JWT] ${event.toUpperCase()} | ${details}`,
    );
  }

  // Логирование Redis событий
  logRedisEvent(event: string, details: string): void {
    this.logger.log(
      `🗄️ [REDIS] ${event.toUpperCase()} | ${details}`,
    );
  }

  // Логирование аномалий
  logAnomaly(protocol: string, email: string, anomalyScore: any): void {
    const severity = anomalyScore.score > 0.8 ? 'CRITICAL' : anomalyScore.score > 0.6 ? 'HIGH' : 'MEDIUM';

    this.logger.log(
      `🚨 [ANOMALY_DETECTED] ${severity} score: ${anomalyScore.score.toFixed(2)} for ${email} via ${protocol}`,
    );

    // Логируем в файл для аудита
    // this.logToFile('ANOMALY_DETECTED', {
    //   protocol,
    //   email,
    //   anomalyScore,
    //   timestamp: new Date().toISOString(),
    // });
  }
}
