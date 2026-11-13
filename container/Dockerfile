# SLAPS container server, built from source. Build context: repository root.
#   docker compose -f container/compose.yaml up -d --build
# The Windows/Linux agent files that "Add client" puts into packages are not built here (the Windows agent needs
# the .NET Framework compiler): copy them from a release package into container/agent-package/ first.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/StandaloneLaps.Server/ src/StandaloneLaps.Server/
COPY web/IisVault/App_Code/AppVersion.cs web/IisVault/App_Code/
COPY web/IisVault/style.css web/IisVault/icon.svg web/IisVault/favicon.ico web/IisVault/icon-180.png web/IisVault/
RUN dotnet publish src/StandaloneLaps.Server/StandaloneLaps.Server.csproj -c Release -o /app -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app ./
COPY container/agent-package/ /app/agent-package/
RUN mkdir -p /data && chown "$APP_UID" /data
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS= \
    Slaps__DataDirectory=/data \
    Slaps__AgentPackageDirectory=/app/agent-package
USER $APP_UID
VOLUME /data
EXPOSE 8443 8444
HEALTHCHECK --interval=60s --timeout=10s --start-period=60s CMD ["dotnet", "StandaloneLaps.Server.dll", "health"]
ENTRYPOINT ["dotnet", "StandaloneLaps.Server.dll"]
