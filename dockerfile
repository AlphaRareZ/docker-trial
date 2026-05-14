# Stage 1: Build - Used to build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copy the project file and restore dependencies
COPY *.csproj .
RUN dotnet restore "AuthenticationService.csproj"

# Copy the remaining source code and build the application
COPY . .
RUN dotnet publish "AuthenticationService.csproj" -c Release -o /app/publish

# Stage 2: Runtime - The final, smaller image to run the application
FROM  mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "AuthenticationService.dll"]