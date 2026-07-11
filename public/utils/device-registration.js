const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;

export const EMPTY_DEVICE_REGISTRATION = Object.freeze({
  name: '',
  host: '',
  port: 830,
  username: '',
  auth_method: 'agent',
  password_env: '',
});

export class DeviceRegistrationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DeviceRegistrationError';
  }
}

export function buildDeviceRegistration(form = {}) {
  const name = String(form.name || '').trim();
  const host = String(form.host || '').trim();
  const username = String(form.username || '').trim();
  const port = Number(form.port || 830);
  const authMethod = form.auth_method || 'agent';

  if (!name || !host || !username) {
    throw new DeviceRegistrationError('Name, host, and username are required.');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new DeviceRegistrationError('Device port is invalid.');
  }
  if (!['agent', 'password-env'].includes(authMethod)) {
    throw new DeviceRegistrationError('Authentication method is invalid.');
  }

  const result = { name, host, port, username, auth_method: authMethod };
  if (authMethod === 'password-env') {
    const passwordEnv = String(form.password_env || '').trim();
    if (!ENV_NAME.test(passwordEnv)) {
      throw new DeviceRegistrationError('Password environment variable name is invalid.');
    }
    result.password_env = passwordEnv;
  }
  return result;
}
