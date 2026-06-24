import { Controller } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import type {
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

@Controller()
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @GrpcMethod('AuthService', 'Register')
    async register(data: RegisterRequest): Promise<RegisterResponse> {
        return this.authService.register(data);
    }

    @GrpcMethod('AuthService', 'Login')
    async login(data: LoginRequest): Promise<LoginResponse> {
        return this.authService.login(data);
    }

    @GrpcMethod('AuthService', 'VerifyOtp')
    async verifyOtp(data: VerifyOtpRequest): Promise<VerifyOtpResponse> {
        return this.authService.verifyOtp(data);
    }

    @GrpcMethod('AuthService', 'Refresh')
    async refresh(data: RefreshRequest): Promise<RefreshResponse> {
        return this.authService.refresh(data);
    }

    @GrpcMethod('AuthService', 'LoginWithGoogle')
    async loginWithGoogle(
        data: LoginWithGoogleRequest,
    ): Promise<LoginWithGoogleResponse> {
        return this.authService.loginWithGoogle(data);
    }

    @GrpcMethod('AuthService', 'DeleteUser')
    async deleteUser(data: DeleteUserRequest): Promise<DeleteUserResponse> {
        return this.authService.deleteUser(data);
    }

    @GrpcMethod('AuthService', 'UpdateEmail')
    async updateEmail(data: UpdateEmailRequest): Promise<UpdateEmailResponse> {
        return this.authService.updateEmail(data);
    }

    @GrpcMethod('AuthService', 'GetProfileAuth')
    async getProfileAuth(
        data: GetProfileAuthRequest,
    ): Promise<GetProfileAuthResponse> {
        return this.authService.getProfileAuth(data);
    }
}