import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService extends Redis implements OnModuleInit, OnModuleDestroy {
  constructor(private configService: ConfigService) {
    const redisUrl = configService.get<string>('REDIS_URL');
    if (!redisUrl) {
      throw new Error('REDIS_URL is not defined in .env');
    }

    super(redisUrl);
  }

  async onModuleInit() {
    await this.ping();
    console.log('Successfully connected to Redis');
  }

  onModuleDestroy() {
    this.quit();
  }
}