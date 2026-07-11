import { DeviceRegistrationError } from './device-registration.js';
import { bridgeErrorMessage } from './bridge-client.js';

const OPERATION_FALLBACKS = Object.freeze({
  connection: 'Connection failed. Check the bridge service and try again.',
  'add-device': 'Failed to add device.',
  'remove-device': 'Failed to remove device.',
});

const REGISTRATION_MESSAGES = new Set([
  'Name, host, and username are required.',
  'Device port is invalid.',
  'Authentication method is invalid.',
  'Password environment variable name is invalid.',
]);

const DEFAULT_HOST_KEY_VERIFICATION = Object.freeze({
  url: '',
  mode: 'strict',
});

export function confirmedHostKeyVerification(
  normalizedUrl,
  reportedMode,
  previousVerification = DEFAULT_HOST_KEY_VERIFICATION,
) {
  const url = String(normalizedUrl || '');
  if (!url) return DEFAULT_HOST_KEY_VERIFICATION;
  if (!['strict', 'disabled-development'].includes(reportedMode)) {
    return retainHostKeyVerificationForUrl(previousVerification, url);
  }
  return Object.freeze({
    url,
    mode: reportedMode,
  });
}

export function retainHostKeyVerificationForUrl(verification, normalizedUrl) {
  if (normalizedUrl && verification?.url === normalizedUrl) return verification;
  return DEFAULT_HOST_KEY_VERIFICATION;
}

export function isHostKeyVerificationDisabledForUrl(verification, normalizedUrl) {
  return Boolean(
    normalizedUrl
    && verification?.url === normalizedUrl
    && verification.mode === 'disabled-development',
  );
}

export function bridgeDisplayError(operation, error) {
  if (
    error instanceof DeviceRegistrationError
    && REGISTRATION_MESSAGES.has(error.message)
  ) {
    return error.message;
  }
  return bridgeErrorMessage(
    error,
    OPERATION_FALLBACKS[operation] || 'Bridge operation failed.',
  );
}

export function createLatestBridgeAttemptGuard() {
  let generation = 0;

  return Object.freeze({
    begin() {
      const attemptGeneration = ++generation;
      return Object.freeze({
        isCurrent: () => attemptGeneration === generation,
        commit(update) {
          if (attemptGeneration !== generation) return false;
          update();
          return true;
        },
      });
    },
    invalidate() {
      generation += 1;
    },
  });
}

export function createExclusiveBridgeMutationLock() {
  let owner = null;

  return Object.freeze({
    acquire() {
      if (owner) return null;
      const token = Symbol('bridge-mutation');
      owner = token;
      return Object.freeze({
        release() {
          if (owner !== token) return false;
          owner = null;
          return true;
        },
      });
    },
    reset() {
      owner = null;
    },
  });
}
