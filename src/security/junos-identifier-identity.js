/** Encode internal identifier components without delimiter ambiguity. */
export function encodeJunosIdentifierTuple(...parts) {
  if (parts.some(part => typeof part !== 'string')) {
    throw new TypeError('Junos identifier tuple parts must be strings');
  }
  return JSON.stringify(parts);
}

export function encodeJunosZonePair(fromZone, toZone) {
  return encodeJunosIdentifierTuple(fromZone, toZone);
}
