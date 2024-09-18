import { IsBoolean } from 'class-validator';

export class EnableTwoFactorDto {
  @IsBoolean()
  enable: boolean;
}
