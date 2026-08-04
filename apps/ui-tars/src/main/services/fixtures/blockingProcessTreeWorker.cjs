const { spawn } = require('node:child_process');

process.once('message', (command) => {
  const heartbeatPath = command.arguments.heartbeatPath;
  const grandchild = spawn(
    process.execPath,
    [
      '-e',
      "const fs=require('node:fs');const path=process.argv[1];setInterval(()=>fs.appendFileSync(path,'x'),10)",
      heartbeatPath,
    ],
    { stdio: 'ignore' },
  );
  process.send({
    operationId: command.operationId,
    identity: command.identity,
    ok: true,
    result: { grandchildPid: grandchild.pid },
  });
});

setInterval(() => undefined, 1_000);
