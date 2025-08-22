/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma.service';
import { SecurityLoggerService } from '../security-logger.service';
import * as crypto from 'crypto';
import * as QRCode from 'qrcode';

interface TOTPConfig {
  issuer: string;
  algorithm: string;
  digits: number;
  period: number;
}

@Injectable()
export class TwoFactorAuthService {
  private readonly totpConfig: TOTPConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
    private readonly securityLogger: SecurityLoggerService,
  ) {
    this.totpConfig = {
      issuer: this.configService.get('TOTP_ISSUER', 'Auth Microservice'),
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    };
  }

  // Генерация секретного ключа для 2FA
  generateSecret(): string {
    return crypto.randomBytes(20).toString('base64');
  }

  // Генерация QR кода для Google Authenticator
  async generateQRCode(
    userId: string,
    email: string,
    secret: string,
  ): Promise<string> {
    const otpauth = `otpauth://totp/${this.totpConfig.issuer}:${email}?secret=${secret}&issuer=${this.totpConfig.issuer}&algorithm=${this.totpConfig.algorithm}&digits=${this.totpConfig.digits}&period=${this.totpConfig.period}`;

    try {
      const qrCode = await QRCode.toDataURL(otpauth);
      this.securityLogger.logSuccess(
        'localhost',
        'QR_CODE_GENERATED',
        `User: ${userId}`,
      );
      return qrCode;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'QR_CODE_ERROR',
        `Failed to generate QR code: ${error.message}`,
      );
      throw error;
    }
  }

  // Включение 2FA для пользователя
  async enable2FA(
    userId: string,
    secret: string,
  ): Promise<{ qrCode: string; backupCodes: string[] }> {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Генерируем backup коды
    const backupCodes = this.generateBackupCodes();

    // Обновляем пользователя
    await this.prismaService.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: secret,
        twoFactorEnabled: true,
        backupCodes: backupCodes,
      },
    });

    // Генерируем QR код
    const qrCode = await this.generateQRCode(userId, user.email, secret);

    this.securityLogger.logSuccess(
      'localhost',
      '2FA_ENABLED',
      `User: ${userId}`,
    );

    return { qrCode, backupCodes };
  }

  // Отключение 2FA
  async disable2FA(userId: string): Promise<void> {
    await this.prismaService.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: null,
        twoFactorEnabled: false,
        backupCodes: [],
      },
    });

    this.securityLogger.logSuccess(
      'localhost',
      '2FA_DISABLED',
      `User: ${userId}`,
    );
  }

  // Проверка TOTP кода
  verifyTOTP(secret: string, token: string): boolean {
    const now = Math.floor(Date.now() / 1000);
    const window = 1; // Допускаем отклонение в 1 период (30 секунд)

    for (let i = -window; i <= window; i++) {
      const time = now + i * this.totpConfig.period;
      const expectedToken = this.generateTOTP(secret, time);

      if (token === expectedToken) {
        return true;
      }
    }

    return false;
  }

  // Проверка backup кода
  async verifyBackupCode(userId: string, backupCode: string): Promise<boolean> {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.backupCodes) {
      return false;
    }

    const codes = user.backupCodes as string[];
    const isValid = codes.includes(backupCode);

    if (isValid) {
      // Удаляем использованный код
      const updatedCodes = codes.filter((code) => code !== backupCode);
      await this.prismaService.user.update({
        where: { id: userId },
        data: { backupCodes: updatedCodes },
      });
    }

    return isValid;
  }

  // Генерация TOTP кода
  private generateTOTP(secret: string, time: number): string {
    const counter = Math.floor(time / this.totpConfig.period);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

    const key = Buffer.from(secret, 'base64');
    const hmac = crypto.createHmac('sha1', key);
    hmac.update(counterBuffer);
    const hash = hmac.digest();

    const offset = hash[hash.length - 1] & 0xf;
    const code =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);

    return (code % Math.pow(10, this.totpConfig.digits))
      .toString()
      .padStart(this.totpConfig.digits, '0');
  }

  // Генерация backup кодов
  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < 10; i++) {
      const code = crypto.randomInt(100000, 999999).toString();
      codes.push(code);
    }
    return codes;
  }
}
