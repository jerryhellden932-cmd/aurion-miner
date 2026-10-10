// Native Node/OpenSSL ML-DSA fixture. All generated keys remain in this process;
// only standard public SPKI encodings and public signatures cross the pipes.
import {createPublicKey, generateKeyPairSync, sign, verify} from 'node:crypto';

const MAX_INPUT = 128 * 1024, SIGNATURE_BYTES = 3309;
const runtime = {node: process.version, openssl: process.versions.openssl};
const output = value => process.stdout.write(JSON.stringify(value) + '\n');

function hex(value, limit, size) {
  if (typeof value !== 'string' || value.length > limit * 2 || value.length % 2 ||
      !/^[0-9a-f]*(?![\s\S])/.test(value) || (size !== undefined && value.length !== size * 2))
    throw new Error('Invalid bounded hexadecimal fixture input.');
  return Buffer.from(value, 'hex');
}
function inputs(record) {
  const context = hex(record.context, 255), otherContext = hex(record.other_context, 255);
  if (!context.length || !otherContext.length || context.equals(otherContext))
    throw new Error('The fixture requires distinct nonempty FIPS contexts.');
  return {message: hex(record.message, 16384), changed: hex(record.changed_message, 16384), context, otherContext};
}
function checks(key, signature, record) {
  const {message, changed, context, otherContext} = inputs(record);
  const corrupted = Buffer.from(signature); corrupted[0] ^= 1;
  return {valid: verify(null, message, {key, context}, signature),
    changed_body: verify(null, changed, {key, context}, signature),
    wrong_context: verify(null, message, {key, context: otherContext}, signature),
    omitted_context: verify(null, message, key, signature),
    corrupted_signature: verify(null, message, {key, context}, corrupted)};
}

let current, replacement;
try {
  current = generateKeyPairSync('ml-dsa-65'); replacement = generateKeyPairSync('ml-dsa-65');
  const message = Buffer.from('ephemeral context capability probe'), context = Buffer.from('Aurion/interop/probe');
  const signature = sign(null, message, {key: current.privateKey, context});
  if (!verify(null, message, {key: current.publicKey, context}, signature) ||
      verify(null, message, {key: current.publicKey, context: Buffer.from('wrong-domain')}, signature) ||
      verify(null, message, current.publicKey, signature))
    throw new Error('Native ML-DSA FIPS context handling is unavailable or ignored.');
} catch (error) {
  output({supported: false, runtime, reason: String(error.message).slice(0, 512)});
  process.exit(0);
}
output({supported: true, runtime,
  current_spki: current.publicKey.export({format: 'der', type: 'spki'}).toString('hex'),
  replacement_spki: replacement.publicKey.export({format: 'der', type: 'spki'}).toString('hex')});

try {
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_INPUT) throw new Error('Fixture input exceeds size limit.');
    chunks.push(chunk);
  }
  const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!request || Object.keys(request).sort().join(',') !== 'sign,verify' ||
      !Array.isArray(request.sign) || !Array.isArray(request.verify) ||
      request.sign.length + request.verify.length > 8)
    throw new Error('Invalid bounded fixture operations.');
  const verified = request.verify.map(record => {
    const key = createPublicKey({key: hex(record.public_spki, 4096), format: 'der', type: 'spki'});
    if (key.asymmetricKeyType !== 'ml-dsa-65') throw new Error('Unexpected fixture key algorithm.');
    return checks(key, hex(record.signature, SIGNATURE_BYTES, SIGNATURE_BYTES), record);
  });
  const signed = request.sign.map(record => {
    const pair = record.key === 'current' ? current : record.key === 'replacement' ? replacement : null;
    if (!pair) throw new Error('Unknown ephemeral signing key.');
    const {message, context} = inputs(record);
    const signature = sign(null, message, {key: pair.privateKey, context});
    return {signature: signature.toString('hex'), checks: checks(pair.publicKey, signature, record)};
  });
  output({verified, signed});
} catch (error) {
  process.stderr.write(String(error.message).slice(0, 1000) + '\n');
  process.exitCode = 1;
}
