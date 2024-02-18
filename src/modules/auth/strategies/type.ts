export type JWTPayload = {
  email: string;
  sub: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
};
