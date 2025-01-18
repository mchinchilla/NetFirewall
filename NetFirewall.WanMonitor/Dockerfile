FROM mcr.microsoft.com/dotnet/runtime:9.0 AS base
USER $APP_UID
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["NetFirewall.WanMonitor/NetFirewall.WanMonitor.csproj", "NetFirewall.WanMonitor/"]
RUN dotnet restore "NetFirewall.WanMonitor/NetFirewall.WanMonitor.csproj"
COPY . .
WORKDIR "/src/NetFirewall.WanMonitor"
RUN dotnet build "NetFirewall.WanMonitor.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "NetFirewall.WanMonitor.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "NetFirewall.WanMonitor.dll"]
