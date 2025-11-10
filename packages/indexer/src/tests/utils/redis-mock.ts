import { jest } from "@jest/globals";

export const createRedisClientMock = () => ({
  get: jest.fn().mockImplementation(async () => null as string | null),
  set: jest.fn().mockImplementation(async () => undefined),
  del: jest.fn().mockImplementation(async () => undefined),
  scan: jest.fn().mockImplementation(async () => ["0", []] as [string, string[]]),
  duplicate: jest.fn().mockReturnValue({
    on: jest.fn(),
    quit: jest.fn(),
  }),
  on: jest.fn(),
});

export const createRedlockMock = () => ({
  acquire: jest.fn(),
  release: jest.fn(),
});
