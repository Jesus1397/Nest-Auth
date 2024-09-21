import { JwtNotLoggedInGuard } from './jwt-not-logged-in.guard';

describe('JwtNotLoggedInGuard', () => {
  it('should be defined', () => {
    expect(new JwtNotLoggedInGuard()).toBeDefined();
  });
});
