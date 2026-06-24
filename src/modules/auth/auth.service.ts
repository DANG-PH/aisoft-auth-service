import { Injectable, Inject, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RpcException, ClientProxy } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { JwtService } from '@nestjs/jwt';
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager';
import { OAuth2Client, TokenPayload } from 'google-auth-library';
import { randomUUID } from 'crypto';
import { MailerService } from '@nestjs-modules/mailer';
import * as bcrypt from 'bcrypt';
import { AuthEntity } from './auth.entity';
import {
    RegisterRequest,
    RegisterResponse,
    LoginRequest,
    LoginResponse,
    VerifyOtpRequest,
    VerifyOtpResponse,
    RefreshRequest,
    RefreshResponse,
    LoginWithGoogleRequest,
    LoginWithGoogleResponse,
    DeleteUserRequest,
    DeleteUserResponse,
    UpdateEmailRequest,
    UpdateEmailResponse,
    GetProfileAuthRequest,
    GetProfileAuthResponse,
} from 'proto/auth.pb';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    private googleClient: OAuth2Client;

    constructor(
        @InjectRepository(AuthEntity)
        private readonly authRepository: Repository<AuthEntity>,
        private readonly jwtService: JwtService,
        private mailerService: MailerService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        @Inject(String(process.env.RABBIT_USER_SERVICE))
        private readonly userClient: ClientProxy,
    ) {
        this.googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    }

    async register(data: RegisterRequest): Promise<RegisterResponse> {
        if (data.username.includes('@gmail.com')) {
            throw new RpcException({
                code: status.INVALID_ARGUMENT,
                message: 'Tên đăng nhập không được là email',
            });
        }

        const exists = await this.authRepository.findOne({
            where: [{ username: data.username }, { email: data.email }],
        });
        if (exists) {
            throw new RpcException({
                code: status.ALREADY_EXISTS,
                message: 'Tên đăng nhập hoặc email đã tồn tại',
            });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(data.password, salt);

        const newUser = this.authRepository.create({
            username: data.username,
            password: passwordHash,
            email: data.email,
            role: 'USER',
        });

        let saved: AuthEntity;
        try {
            saved = await this.authRepository.save(newUser);
        } catch (err) {
            this.logger.error('Tạo tài khoản thất bại', err);
            throw new RpcException({
                code: status.INTERNAL,
                message: 'Không thể tạo tài khoản',
            });
        }

        this.userClient.emit('user.registered', {
            authId: saved.id,
            realname: data.realname,    
            username: data.username,
        });

        // Welcome email — fire-and-forget
        this.mailerService
            .sendMail({
                to: data.email,
                subject: 'Chào mừng đến với AISoft Demo',
                html: welcomeEmailTemplate(data.username),
            })
            .catch((err) =>
                this.logger.warn(`Gửi welcome email thất bại cho ${data.email}`, err),
            );

        this.logger.log(`Đã emit user.registered cho authId=${saved.id}`);
        return { success: true };
    }

    async login(data: LoginRequest): Promise<LoginResponse> {
        const user = await this.authRepository.findOne({
            where: { username: data.username },
        });
        if (!user || !user.password) {
            throw new RpcException({
                code: status.UNAUTHENTICATED,
                message: 'Tên đăng nhập hoặc mật khẩu không đúng',
            });
        }

        const isLocked = await this.cacheManager.get(`LOCK:${data.username}`);
        if (isLocked) {
            throw new RpcException({
                code: status.PERMISSION_DENIED,
                message: 'Tài khoản tạm khóa 10 phút do nhập sai quá nhiều lần',
            });
        }

        const passwordMatch = await bcrypt.compare(data.password, user.password);
        if (!passwordMatch) {
            const attempts = await this.incrementLoginAttempt(data.username);
            if (attempts > 5) {
                await this.cacheManager.set(
                    `LOCK:${user.username}`,
                    true,
                    10 * 60 * 1000,
                );
                throw new RpcException({
                    code: status.UNAUTHENTICATED,
                    message: 'Sai mật khẩu quá nhiều lần. Tài khoản bị khóa 10 phút',
                });
            }
            throw new RpcException({
                code: status.UNAUTHENTICATED,
                message: 'Tên đăng nhập hoặc mật khẩu không đúng',
            });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await this.cacheManager.set(`OTP:${user.username}`, otp, 5 * 60 * 1000);

        this.mailerService
            .sendMail({
                to: user.email,
                subject: 'Mã OTP đăng nhập — AISoft Demo',
                html: otpEmailTemplate(user.username, otp),
            })
            .catch((err) =>
                this.logger.warn(`Gửi OTP email thất bại cho ${user.email}`, err),
            );

        this.logger.log(`Đã gửi OTP cho ${user.username} (${user.email})`);

        const sessionId = Buffer.from(user.username).toString('base64');
        return { sessionId };
    }

    async verifyOtp(data: VerifyOtpRequest): Promise<VerifyOtpResponse> {
        const username = Buffer.from(data.sessionId, 'base64').toString('ascii');
        const user = await this.authRepository.findOne({ where: { username } });
        if (!user) {
            throw new RpcException({
                code: status.UNAUTHENTICATED,
                message: 'Phiên đăng nhập không hợp lệ',
            });
        }

        const otpInCache = await this.cacheManager.get<string>(`OTP:${username}`);
        if (!otpInCache || otpInCache !== data.otp) {
            throw new RpcException({
                code: status.UNAUTHENTICATED,
                message: 'Mã OTP sai hoặc đã hết hạn',
            });
        }

        await this.cacheManager.del(`OTP:${username}`);
        await this.cacheManager.del(`LOGIN_FAIL:${username}`);

        const tokens = this.generateTokens(user);
        return {
            access_token: tokens.accessToken,
            refresh_token: tokens.refreshToken,
        };
    }

    async refresh(data: RefreshRequest): Promise<RefreshResponse> {
        let decoded: any;
        try {
            decoded = this.jwtService.verify(data.refreshToken);
        } catch (err) {
            throw new RpcException({
                code: status.UNAUTHENTICATED,
                message: 'Refresh token không hợp lệ hoặc đã hết hạn',
            });
        }

        const isBlacklisted = await this.cacheManager.get(
            `BLACKLIST_REFRESH:${decoded.jti}`,
        );
        if (isBlacklisted) {
            throw new RpcException({
                code: status.UNAUTHENTICATED,
                message: 'Refresh token đã bị thu hồi',
            });
        }

        const user = await this.authRepository.findOne({
            where: { username: decoded.username },
        });
        if (!user) {
            throw new RpcException({
                code: status.UNAUTHENTICATED,
                message: 'Người dùng không tồn tại',
            });
        }

        const now = Math.floor(Date.now() / 1000);
        const ttl = Math.max(decoded.exp - now, 0);
        if (ttl > 0) {
            await this.cacheManager.set(
                `BLACKLIST_REFRESH:${decoded.jti}`,
                true,
                ttl * 1000,
            );
        }

        const tokens = this.generateTokens(user);
        return {
            access_token: tokens.accessToken,
            refresh_token: tokens.refreshToken,
        };
    }

    async loginWithGoogle(
        data: LoginWithGoogleRequest,
    ): Promise<LoginWithGoogleResponse> {
        const tokenPayload = await this.verifyGoogleToken(data.tokenFromGoogle);

        if (!tokenPayload.email_verified) {
            throw new RpcException({
                code: status.PERMISSION_DENIED,
                message: 'Email Google chưa được xác thực',
            });
        }

        if (!tokenPayload.email || !tokenPayload.name) {
            throw new RpcException({
                code: status.PERMISSION_DENIED,
                message: 'Token Google thiếu thông tin, vui lòng thử lại',
            });
        }

        let user = await this.authRepository.findOne({
            where: { username: tokenPayload.email },
        });
        let isNewUser = false;

        if (!user) {
            isNewUser = true;
            user = await this.registerWithGoogle(tokenPayload);
        }

        const tokens = this.generateTokens(user);
        return {
            access_token: tokens.accessToken,
            refresh_token: tokens.refreshToken,
            register: isNewUser,
        };
    }

    async deleteUser(data: DeleteUserRequest): Promise<DeleteUserResponse> {
        const user = await this.authRepository.findOne({
            where: { id: data.userId },
        });
        if (!user) {
            throw new RpcException({
                code: status.NOT_FOUND,
                message: 'Tài khoản không tồn tại',
            });
        }

        try {
            await this.authRepository.delete(data.userId);

            this.userClient.emit('user.deleted', {
                authId: data.userId,
            });
            this.logger.log(`Đã emit user.deleted cho authId=${data.userId}`);

            return { success: true };
        } catch (err) {
            this.logger.error(`Xóa tài khoản ${data.userId} thất bại`, err);
            throw new RpcException({
                code: status.INTERNAL,
                message: 'Không thể xóa tài khoản',
            });
        }
    }

    async updateEmail(data: UpdateEmailRequest): Promise<UpdateEmailResponse> {
        const user = await this.authRepository.findOne({
            where: { id: data.userId },
        });
        if (!user) {
            throw new RpcException({
                code: status.NOT_FOUND,
                message: 'Tài khoản không tồn tại',
            });
        }

        const existing = await this.authRepository.findOne({
            where: { email: data.email },
        });
        if (existing && existing.id !== data.userId) {
            throw new RpcException({
                code: status.ALREADY_EXISTS,
                message: 'Email đã được sử dụng',
            });
        }

        const oldEmail = user.email;
        user.email = data.email;
        try {
            await this.authRepository.save(user);

            // Thông báo email mới
            this.mailerService
                .sendMail({
                    to: data.email,
                    subject: 'Email đã được cập nhật — AISoft Demo',
                    html: emailChangedTemplate(user.username, data.email),
                })
                .catch((err) =>
                    this.logger.warn(
                        `Gửi notification email mới thất bại: ${data.email}`,
                        err,
                    ),
                );

            // Cảnh báo email cũ (bảo mật: phòng trường hợp bị hack)
            this.mailerService
                .sendMail({
                    to: oldEmail,
                    subject: '[CẢNH BÁO] Email tài khoản đã thay đổi — AISoft Demo',
                    html: emailChangedTemplate(user.username, data.email),
                })
                .catch((err) =>
                    this.logger.warn(
                        `Gửi cảnh báo email cũ thất bại: ${oldEmail}`,
                        err,
                    ),
                );

            return { success: true };
        } catch (err) {
            this.logger.error(`Cập nhật email cho ${data.userId} thất bại`, err);
            throw new RpcException({
                code: status.INTERNAL,
                message: 'Không thể cập nhật email',
            });
        }
    }

    async getProfileAuth(
        data: GetProfileAuthRequest,
    ): Promise<GetProfileAuthResponse> {
        const user = await this.authRepository.findOne({
            where: { id: data.userId },
        });
        if (!user) {
            throw new RpcException({
                code: status.NOT_FOUND,
                message: 'Tài khoản không tồn tại',
            });
        }

        return {
            username: user.username,
            email: user.email,
            role: user.role,
        };
    }

    private generateTokens(
        user: AuthEntity,
    ): { accessToken: string; refreshToken: string } {
        const accessPayload = {
            userId: user.id,
            username: user.username,
            role: user.role,
            tokenVersion: user.tokenVersion ?? 0,
        };

        const accessToken = this.jwtService.sign(accessPayload, {
            expiresIn: '1d',
        });

        const refreshToken = this.jwtService.sign(
            { username: user.username, jti: randomUUID() },
            { expiresIn: '7d' },
        );

        return { accessToken, refreshToken };
    }

    private async incrementLoginAttempt(username: string): Promise<number> {
        const key = `LOGIN_FAIL:${username}`;
        let attempts = (await this.cacheManager.get<number>(key)) || 0;
        attempts++;
        await this.cacheManager.set(key, attempts, 15 * 60 * 1000);
        return attempts;
    }

    private async verifyGoogleToken(idToken: string): Promise<TokenPayload> {
        try {
            const ticket = await this.googleClient.verifyIdToken({
                idToken,
                audience: process.env.GOOGLE_CLIENT_ID,
            });
            const payload = ticket.getPayload();
            if (!payload) {
                throw new Error('Token Google không có payload');
            }
            return payload;
        } catch (err) {
            throw new RpcException({
                code: status.UNAUTHENTICATED,
                message: 'Token Google không hợp lệ hoặc đã hết hạn',
            });
        }
    }

    private async registerWithGoogle(
        tokenPayload: TokenPayload,
    ): Promise<AuthEntity> {
        const randomPassword = generateStrongPassword();
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(randomPassword, salt);

        const newUser = this.authRepository.create({
            username: tokenPayload.email,
            password: passwordHash,
            email: tokenPayload.email,
            role: 'USER',
            type: 1,                     
        });

        let saved: AuthEntity;
        try {
            saved = await this.authRepository.save(newUser);
        } catch (err) {
            this.logger.error('Tạo tài khoản Google thất bại', err);
            throw new RpcException({
                code: status.INTERNAL,
                message: 'Không thể tạo tài khoản Google',
            });
        }

        this.userClient.emit('user.registered', {
            authId: saved.id,
            realname: tokenPayload.name,
            username: tokenPayload.email,
        });

        // Gửi mail kèm password ngẫu nhiên để user biết có thể login bằng username/password
        // (ngoài việc login bằng Google)
        this.mailerService
            .sendMail({
                to: tokenPayload.email,
                subject: 'Chào mừng đến với AISoft Demo',
                html: welcomeEmailTemplate(tokenPayload.email, randomPassword),
            })
            .catch((err) =>
                this.logger.warn(
                    `Gửi welcome email (Google) thất bại cho ${tokenPayload.email}`,
                    err,
                ),
            );

        this.logger.log(`Đã emit user.registered (Google) cho authId=${saved.id}`);
        return saved;
    }
}

function generateStrongPassword(length = 14): string {
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+-=[]{};:,.<>?';
    const all = lower + upper + numbers + special;

    const password = [
        lower[Math.floor(Math.random() * lower.length)],
        upper[Math.floor(Math.random() * upper.length)],
        numbers[Math.floor(Math.random() * numbers.length)],
        special[Math.floor(Math.random() * special.length)],
    ];

    for (let i = 0; i < length - 4; i++) {
        password.push(all[Math.floor(Math.random() * all.length)]);
    }

    return password.sort(() => Math.random() - 0.5).join('');
}

// ============================================================
// EMAIL TEMPLATES DEMO
// ============================================================
function otpEmailTemplate(username: string, otp: string): string {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2c3e50;">Xác thực đăng nhập</h2>
            <p>Xin chào <b>${username}</b>,</p>
            <p>Mã OTP của bạn là:</p>
            <div style="font-size: 32px; font-weight: bold; color: #e74c3c; 
                        letter-spacing: 8px; text-align: center; 
                        padding: 20px; background: #f8f9fa; border-radius: 8px;
                        margin: 20px 0;">
                ${otp}
            </div>
            <p style="color: #7f8c8d;">Mã có hiệu lực trong <b>5 phút</b>.</p>
            <p style="color: #7f8c8d; font-size: 12px;">
                Nếu bạn không yêu cầu, vui lòng bỏ qua email này.
            </p>
            <hr style="border: none; border-top: 1px solid #ecf0f1;">
            <p style="color: #95a5a6; font-size: 11px;">AISoft Demo</p>
        </div>
    `;
}

function welcomeEmailTemplate(username: string, password?: string): string {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #27ae60;">Chào mừng bạn đến với AISoft Demo!</h2>
            <p>Xin chào <b>${username}</b>,</p>
            <p>Tài khoản của bạn đã được tạo thành công.</p>
            ${
                password
                    ? `<div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0;">
                        <p style="margin: 0;"><b>Username:</b> ${username}</p>
                        <p style="margin: 8px 0 0 0;"><b>Mật khẩu tạm:</b> ${password}</p>
                        <p style="color: #856404; margin-top: 12px; font-size: 13px;">
                            Vui lòng đổi mật khẩu sau khi đăng nhập lần đầu.
                        </p>
                    </div>`
                    : ''
            }
            <p style="color: #7f8c8d;">Chúc bạn có trải nghiệm tuyệt vời.</p>
            <hr style="border: none; border-top: 1px solid #ecf0f1;">
            <p style="color: #95a5a6; font-size: 11px;">AISoft Demo</p>
        </div>
    `;
}

function emailChangedTemplate(username: string, newEmail: string): string {
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #3498db;">Email đã được cập nhật</h2>
            <p>Xin chào <b>${username}</b>,</p>
            <p>Email tài khoản của bạn đã được đổi sang: <b>${newEmail}</b></p>
            <p style="color: #e74c3c;">
                Nếu không phải bạn thực hiện, vui lòng liên hệ Admin ngay.
            </p>
            <hr style="border: none; border-top: 1px solid #ecf0f1;">
            <p style="color: #95a5a6; font-size: 11px;">AISoft Demo</p>
        </div>
    `;
}