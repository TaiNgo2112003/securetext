# Bước 1: Dùng SDK để build
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["SecureText.csproj", "./"]
RUN dotnet restore "./SecureText.csproj"
COPY . .
RUN dotnet publish "./SecureText.csproj" -c Release -o /app/publish

# Bước 2: Copy build output và chạy
FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "SecureText.dll"]
