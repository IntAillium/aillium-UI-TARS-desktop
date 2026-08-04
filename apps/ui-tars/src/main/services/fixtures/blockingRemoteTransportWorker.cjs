const net = require('node:net');

process.once('message', (command) => {
  const socket = net.createConnection(command.arguments.socketPath);
  socket.once('connect', () => {
    process.send({
      operationId: command.operationId,
      identity: command.identity,
      ok: true,
      result: { connected: true },
    });
  });
});

setInterval(() => undefined, 1_000);
