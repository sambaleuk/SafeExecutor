import { loadConfig, loadPolicy } from '../src/config/loader.js';

describe('loadConfig / loadPolicy — repeated loads', () => {
  test('the same config can be loaded more than once in a process', () => {
    expect(() => {
      loadConfig('./config/example-config.json');
      loadConfig('./config/example-config.json');
    }).not.toThrow();
  });

  test('the same policy can be loaded more than once in a process', () => {
    expect(() => {
      loadPolicy('./config/default-policy.json');
      loadPolicy('./config/default-policy.json');
    }).not.toThrow();
  });
});
