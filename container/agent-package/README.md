# Agent files for client packages

"Add client" in the container portal builds client packages from the files in this folder
(inside the image: `/app/agent-package`). They are not part of the source build because the
Windows agent is compiled with the .NET Framework compiler on Windows.

Copy them from the matching release package (`StandaloneLaps-Container-<version>.zip` already
contains them, or the server package `StandaloneLaps-Server-<version>.zip`):

| From the server package | To this folder |
|---|---|
| `agent/StandaloneLaps.Agent.exe` | `StandaloneLaps.Agent.exe` |
| `agent/StandaloneLaps.Agent.exe.config` | `StandaloneLaps.Agent.exe.config` |
| `client/Install-SlapsAgent.ps1` | `Install-SlapsAgent.ps1` |
| `linux/slaps-agent`, `slaps-agent.service`, `agent.conf`, `install.sh` | `linux/` (same names) |
| `linux/slaps-agent_<version>_all.deb` | `linux/slaps-agent.deb` |

Use the signed release files so Defender/ASR accepts the agent and installer on Windows servers.
