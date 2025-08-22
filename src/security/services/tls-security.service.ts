/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { readFileSync } from 'fs';
import { join } from 'path';
import { SecurityLoggerService } from '../security-logger.service';

@Injectable()
export class TlsSecurityService {
  constructor(
    private readonly configService: ConfigService,
    private readonly securityLogger: SecurityLoggerService,
  ) {}

  // Получение TLS credentials для gRPC сервера
  getTlsCredentials() {
    try {
      const certPath = this.configService.get(
        'TLS_CERT_PATH',
        './certs/server.crt',
      );
      const keyPath = this.configService.get(
        'TLS_KEY_PATH',
        './certs/server.key',
      );
      const caPath = this.configService.get('TLS_CA_PATH', './certs/ca.crt');

      const cert = readFileSync(join(process.cwd(), certPath));
      const key = readFileSync(join(process.cwd(), keyPath));
      const ca = readFileSync(join(process.cwd(), caPath));

      this.securityLogger.logSuccess(
        'localhost',
        'TLS_CREDENTIALS_LOADED',
        'TlsSecurityService',
      );

      return {
        cert,
        key,
        ca,
        checkServerIdentity: () => undefined, // Отключаем проверку hostname для внутренних сервисов
      };
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TLS_CREDENTIALS_ERROR',
        `Failed to load TLS credentials: ${error.message}`,
      );
      throw new Error(
        'TLS credentials not found. Please configure TLS certificates.',
      );
    }
  }

  // Проверка TLS конфигурации
  validateTlsConfig(): boolean {
    const requiredVars = [
      'TLS_CERT_PATH',
      'TLS_KEY_PATH',
      'TLS_CA_PATH',
      'TLS_ENABLED',
    ];

    const missingVars = requiredVars.filter(
      (varName) => !this.configService.get(varName),
    );

    if (missingVars.length > 0) {
      this.securityLogger.logSecurityError(
        'TLS_CONFIG_ERROR',
        `Missing TLS variables: ${missingVars.join(', ')}`,
      );
      return false;
    }

    return true;
  }

  // Получение TLS порта
  getTlsPort(): number {
    return this.configService.get('TLS_PORT', 50052);
  }

  // Проверка необходимости TLS
  isTlsEnabled(): boolean {
    return this.configService.get('TLS_ENABLED', 'false') === 'true';
  }
}
