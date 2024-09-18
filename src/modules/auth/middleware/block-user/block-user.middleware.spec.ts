import { BlockUserMiddleware } from './block-user.middleware';

describe('BlockUserMiddleware', () => {
  it('should be defined', () => {
    expect(new BlockUserMiddleware()).toBeDefined();
  });
});
