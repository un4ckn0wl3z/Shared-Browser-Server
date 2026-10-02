# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY server/SharedBrowser.Server.csproj server/
RUN dotnet restore server/SharedBrowser.Server.csproj

COPY server/ server/
RUN dotnet publish server/SharedBrowser.Server.csproj \
    --configuration Release \
    --output /publish \
    --no-restore \
    -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

COPY --from=build /publish/ ./

RUN mkdir -p /data && chown -R app:app /data

ENV ASPNETCORE_URLS=http://0.0.0.0:8787 \
    SHARED_BROWSER_DATA=/data \
    SHARED_BROWSER_PROXY_BIND=0.0.0.0

EXPOSE 8787 8899

USER app
ENTRYPOINT ["dotnet", "SharedBrowser.Server.dll"]
