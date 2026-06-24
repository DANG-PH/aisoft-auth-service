import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthEntity } from './auth.entity';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';

@Module({
  imports: [
    // Đăng kí client RabbitMQ
    ClientsModule.register([
      // User client
      {
        name: process.env.RABBIT_USER_SERVICE,
        transport: Transport.RMQ,
        options: {
          urls: [process.env.RABBIT_URL],
          queue: process.env.RABBIT_USER_QUEUE,
          queueOptions: { durable: true },
        },
      },
    ]),

    MailerModule.forRootAsync({
      useFactory: async (config: ConfigService) => ({
        transport: {
          host: 'smtp.gmail.com',
          port: 465,
          secure: true,
          auth: {
            user: config.get<string>('MAIL_USER'),
            pass: config.get<string>('MAIL_PASS'),
          },
        },
        defaults: {
          from: `"AISoft Demo" <${config.get<string>('MAIL_USER')}>`,
        },
      }),
      inject: [ConfigService],
    }),

    TypeOrmModule.forFeature([AuthEntity]),

    JwtModule.registerAsync({
      useFactory: async (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [AuthService],
  exports: [AuthService, JwtModule],
  controllers: [AuthController],
})
export class AuthModule {}