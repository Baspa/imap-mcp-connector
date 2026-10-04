import { GenericContainer, Wait } from 'testcontainers';
import type { TestProject } from 'vitest/node';

declare module 'vitest' {
  export interface ProvidedContext {
    greenmail: { host: string; smtpPort: number; imapPort: number; apiPort: number };
  }
}

export default async function setup(project: TestProject) {
  const container = await new GenericContainer('greenmail/standalone:2.1.5')
    .withEnvironment({
      GREENMAIL_OPTS: [
        '-Dgreenmail.setup.test.all',
        '-Dgreenmail.hostname=0.0.0.0',
        '-Dgreenmail.users.login=email',
        '-Dgreenmail.api.hostname=0.0.0.0',
        '-Dgreenmail.api.port=8080',
      ].join(' '),
    })
    .withExposedPorts(3025, 3143, 8080)
    .withWaitStrategy(Wait.forListeningPorts())
    .withStartupTimeout(120_000)
    .start();

  project.provide('greenmail', {
    host: container.getHost(),
    smtpPort: container.getMappedPort(3025),
    imapPort: container.getMappedPort(3143),
    apiPort: container.getMappedPort(8080),
  });

  return async () => {
    await container.stop();
  };
}
