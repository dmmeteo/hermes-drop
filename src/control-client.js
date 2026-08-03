// Minimal client for the local control socket: one JSON line out, one JSON line
// back, then the connection closes.
import { connect } from 'node:net';

export function controlRequest(socketPath, request, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let buffer = '';

    const fail = (error) => {
      socket.destroy();
      reject(error);
    };

    socket.setTimeout(timeoutMs, () => fail(new Error('control request timed out')));
    socket.on('error', fail);
    socket.on('connect', () => socket.write(`${JSON.stringify(request)}\n`));
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
    });
    socket.on('end', () => {
      try {
        resolve(JSON.parse(buffer));
      } catch {
        fail(new Error('malformed control response'));
      }
    });
  });
}
