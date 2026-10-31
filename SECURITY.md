# Security policy

locklog lets an AI agent search and count across logs while a console held
by a human reads them: the personal data and secrets locklog detects are
masked before anything reaches the agent. locklog is in development and
has no release yet; this policy describes the target design, in which the
console runs in Docker, in a container and under an account of its own,
which the agent cannot reach. A
flaw in the masking, the console or its socket is a security issue.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub security advisories:
open <https://github.com/DavidGodefroid/locklog/security/advisories/new>
(the "Report a vulnerability" button on the repository's Security tab).

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Please include:

- the locklog version (`locklog version`: the launcher's and the image's)
  and your OS and Docker version;
- the log source (files, journald, containers, Loki, ...) and how the agent
  reaches the console, if relevant;
- the steps or input needed to reproduce the issue, and its impact.

Never include real credentials, tokens, cookies, real personal data or
unmasked log lines in a report: use synthetic values.

You will get an acknowledgement within a week. Fixes are released as soon as
possible, and the advisory is published with credit to the reporter unless
you ask otherwise.

## Scope

Issues of interest include, among others:

- a value of a kind locklog detects (an email address, a phone number, an
  IBAN, a card number, a national id, a public IP address, a secret of a
  known shape) reaching the agent, the audit log or an error message
  unmasked;
- a way for the agent to learn a masked value without a human's approval:
  through search predicates, counts, patterns, result sizes, cursors,
  stopping points or timing;
- a way for the agent to read a log source the human did not approve, to
  write to any log source or backend, or to loosen the policy without the
  human's confirmation;
- a way for the agent to reach the console's account, its home volume or a
  backend credential;
- log content that can spoof the console's approval screen or make locklog
  act beyond the agent's call.

What locklog does not detect will be listed in the README with the first
release, and is not a vulnerability by itself. Attacks that require running code as the console's
OS account, or an agent that can already read the logs, the Docker socket or
the backends directly (a deployment precondition), are out of scope.

## Supported versions

Releases before v1.0.0 are pre-releases. Only the latest release receives
security fixes.
