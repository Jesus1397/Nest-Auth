import { IsNotEmpty, IsString } from 'class-validator';

export class TwoFactorDto {
  @IsString()
  @IsNotEmpty()
  token: string;
}
