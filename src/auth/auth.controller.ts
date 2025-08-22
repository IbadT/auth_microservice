/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
import { Controller, Logger } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
} from './src/auth/auth';
import { SecurityLoggerService } from '../security/security-logger.service';
import { BruteForceService } from '../security/services/brute-force.service';
import { SecureAuthService } from '../security/services/secure-auth.service';
import { EnhancedJwtService } from '../security/services/enhanced-jwt.service';
import { TwoFactorAuthService } from '../security/services/two-factor-auth.service';
import { AnomalyDetectionService } from '../security/services/anomaly-detection.service';
import { EncryptionService } from '../security/services/encryption.service';
import { PrismaService } from '../prisma.service';


// node test-grpc-client.js

@Controller()
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  constructor(
    private readonly authService: AuthService,
    private readonly securityLogger: SecurityLoggerService,
    private readonly bruteForceService: BruteForceService,
    private readonly secureAuthService: SecureAuthService,
    private readonly enhancedJwtService: EnhancedJwtService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly anomalyDetectionService: AnomalyDetectionService,
    private readonly encryptionService: EncryptionService,
    private readonly prismaService: PrismaService,
  ) {}

  @GrpcMethod('AuthService', 'login')
  async login(data: LoginRequest): Promise<LoginResponse> {
    const { email, password } = data;

    this.logger.log(
      `🔐 [AUTH] LOGIN request received for email: ${email}`,
    );

    try {
      // 1. Проверяем brute force блокировку
      const isBlocked = await this.bruteForceService.isBlocked(email);
      if (isBlocked) {
        this.securityLogger.logAuthAttempt('gRPC', email, false);
        throw new Error('Too many failed attempts. Please try again later.');
      }

      // 2. Безопасная аутентификация
      const authResult = await this.secureAuthService.authenticateUser(
        email,
        password,
      );

      if (!authResult.success) {
        // Записываем неудачную попытку
        await this.bruteForceService.recordFailedAttempt(email);
        this.securityLogger.logAuthAttempt('gRPC', email, false);
        throw new Error('Invalid credentials');
      }

      // 3. Анализ аномалий поведения
      const behavior = {
        userId: authResult.user.id,
        ipAddress: 'unknown', // Будет извлечено из gRPC метаданных
        userAgent: 'unknown', // Будет извлечено из gRPC метаданных
        action: 'login',
        success: true,
        timestamp: new Date(),
      };
      
      const anomalyScore = await this.anomalyDetectionService.analyzeUserBehavior(
        authResult.user.id,
        behavior,
      );

      if (anomalyScore.score > 0.7) {
        this.securityLogger.logAnomaly('gRPC', email, anomalyScore);
        // Можно добавить дополнительную проверку или блокировку
      }

      // 4. Генерируем токены с JTI и шифрованием
      const tokens = await this.enhancedJwtService.generateTokens(
        authResult.user.id,
        authResult.user.email,
      );

      // 5. Шифруем чувствительные данные в токенах
      const encryptedAccessToken = this.encryptionService.encrypt(tokens.accessToken);
      const encryptedRefreshToken = this.encryptionService.encrypt(tokens.refreshToken);

      // 6. Проверяем 2FA статус пользователя
      const user = await this.prismaService.user.findUnique({ where: { email } });
      if (user && user.twoFactorEnabled) {
        // Если 2FA включен, возвращаем специальный токен для 2FA проверки
        this.securityLogger.logJwtEvent('2FA_REQUIRED', `User ${email} requires 2FA verification`);
        return {
          accessToken: '2FA_REQUIRED',
          refreshToken: '2FA_REQUIRED',
        };
      }

      // 7. Очищаем счетчик неудачных попыток
      await this.bruteForceService.clearFailedAttempts(email);

      this.securityLogger.logAuthAttempt('gRPC', email, true);
      return {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
      };
    } catch (error) {
      this.securityLogger.logAuthAttempt('gRPC', email, false);
      throw error;
    }
  }

  @GrpcMethod('AuthService', 'register')
  async register(data: RegisterRequest): Promise<RegisterResponse> {
    const { email, password } = data;

    this.logger.log(
      `📝 [AUTH] REGISTER request received for email: ${email}`,
    );

    try {
      // 1. Проверяем сложность пароля
      const passwordValidation =
        this.secureAuthService.validatePasswordStrength(password);
      if (!passwordValidation.valid) {
        this.securityLogger.logRegistration('gRPC', email, false);
        throw new Error(
          `Password validation failed: ${passwordValidation.errors.join(', ')}`,
        );
      }

      // 2. Регистрируем пользователя
      const tokens = await this.authService.register(data);

      this.securityLogger.logRegistration('gRPC', email, true);
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      this.securityLogger.logRegistration('gRPC', email, false);
      throw error;
    }
  }

  @GrpcMethod('AuthService', 'refreshToken')
  async refreshToken(data: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    this.logger.log(
      `🔄 [AUTH] REFRESH_TOKEN request received`,
    );

    try {
      const tokens = await this.authService.refreshToken(data.refreshToken);
      this.securityLogger.logTokenRefresh('gRPC', true);
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      this.securityLogger.logTokenRefresh('gRPC', false);
      throw error;
    }
  }

  @GrpcMethod('AuthService', 'enable2FA')
  async enable2FA(data: { userId: string }): Promise<{ qrCode: string; backupCodes: string[] }> {
    this.logger.log(
      `🔐 [2FA] ENABLE request received for user ${data.userId}`,
    );

    try {
      const result = await this.twoFactorAuthService.enable2FA(data.userId, '');
      this.securityLogger.logJwtEvent('2FA_ENABLED', `User ${data.userId} enabled 2FA`);
      return result;
    } catch (error) {
      this.securityLogger.logSecurityError('2FA_ENABLE_FAILED', error.message);
      throw error;
    }
  }

  @GrpcMethod('AuthService', 'verify2FA')
  async verify2FA(data: { userId: string; token: string }): Promise<{ success: boolean }> {
    this.logger.log(
      `🔐 [2FA] VERIFY request received for user ${data.userId}`,
    );

    try {
      const user = await this.prismaService.user.findUnique({ where: { id: data.userId } });
      if (!user || !user.twoFactorSecret) {
        throw new Error('2FA not enabled for this user');
      }

      const isValid = this.twoFactorAuthService.verifyTOTP(user.twoFactorSecret, data.token);
      this.securityLogger.logJwtEvent('2FA_VERIFIED', `User ${data.userId} 2FA verification: ${isValid}`);
      return { success: isValid };
    } catch (error) {
      this.securityLogger.logSecurityError('2FA_VERIFY_FAILED', error.message);
      throw error;
    }
  }

  @GrpcMethod('AuthService', 'getAnomalyStats')
  async getAnomalyStats(data: { userId: string }): Promise<any> {
    this.logger.log(
      `📊 [ANOMALY] STATS request received for user ${data.userId}`,
    );

    try {
      const stats = await this.anomalyDetectionService.getAnomalyStats(data.userId);
      this.securityLogger.logJwtEvent('ANOMALY_STATS', `Retrieved stats for user ${data.userId}`);
      return stats;
    } catch (error) {
      this.securityLogger.logSecurityError('ANOMALY_STATS_FAILED', error.message);
      throw error;
    }
  }
}
