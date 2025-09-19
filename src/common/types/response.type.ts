import { HttpStatus } from '@nestjs/common';

export type ResponseType<T> = {
  statusCode: HttpStatus;
  message: string;
  success: boolean;
  data: T;
};
