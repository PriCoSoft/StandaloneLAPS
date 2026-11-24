# SLAPS container server, built from source. Build context: repository root.
#   docker compose -f container/compose.yaml up -d --build
# The Windows/Linux agent files that "Add client" puts into packages are not built here (the Windows agent needs
# the .NET Framework compiler): copy them from a release package into container/agent-package/ first.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/StandaloneLaps.Server/ src/StandaloneLaps.Server/
COPY web/IisVault/App_Code/AppVersion.cs web/IisVault/App_Code/WindowsLaps.cs web/IisVault/App_Code/
COPY web/IisVault/style.css web/IisVault/copy.js web/IisVault/icon.svg web/IisVault/favicon.ico web/IisVault/icon-180.png web/IisVault/
COPY container/dpapi/ container/dpapi/
RUN dotnet publish src/StandaloneLaps.Server/StandaloneLaps.Server.csproj -c Release -o /app -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
# Optional Windows LAPS lookup: libldap for System.DirectoryServices.Protocols, Python with dpapi-ng to decrypt
# encrypted Windows LAPS passwords (Linux has no DPAPI-NG). --build-arg SLAPS_DPAPI_KERBEROS=true adds Kerberos
# (gcc/krb5 build); the default authenticates the key lookup with NTLM via pyspnego.
ARG SLAPS_DPAPI_KERBEROS=false
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
 && (apt-get install -y --no-install-recommends libldap2 || apt-get install -y --no-install-recommends libldap-2.5-0) \
 && python3 -m venv /opt/dpapi \
 && if [ "$SLAPS_DPAPI_KERBEROS" = "true" ]; then \
      apt-get install -y --no-install-recommends gcc python3-dev libkrb5-dev krb5-user \
      && /opt/dpapi/bin/pip install --no-cache-dir "dpapi-ng[kerberos]>=0.2,<1"; \
    else /opt/dpapi/bin/pip install --no-cache-dir "dpapi-ng>=0.2,<1"; fi \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app ./
COPY container/agent-package/ /app/agent-package/
RUN mkdir -p /data && chown "$APP_UID" /data
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS= \
    Slaps__DataDirectory=/data \
    Slaps__AgentPackageDirectory=/app/agent-package \
    Slaps__WindowsLapsPython=/opt/dpapi/bin/python
USER $APP_UID
VOLUME /data
EXPOSE 8443 8444
HEALTHCHECK --interval=60s --timeout=10s --start-period=60s CMD ["dotnet", "StandaloneLaps.Server.dll", "health"]
ENTRYPOINT ["dotnet", "StandaloneLaps.Server.dll"]
