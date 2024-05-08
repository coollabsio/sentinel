# Sentinel

An experimental API for gathering Linux server / Docker Engine metrics.

> This will be used in [coolify.io](https://coolify.io).

## Features
### Server
- CPU usage
- Memory usage
- Disk usage
### Containers
- CPU usage
- Memory usage
- Network usage


## Usage
Start as a container:
```bash
docker run -d  -v /var/run/docker.sock:/var/run/docker.sock --pid host --name sentinel ghcr.io/coollabsio/sentinel:latest

# You can expose port 8888 to access the API
# By default, the API is only available in the container, so you need docker exec to access it.
```

## API
### Server
- `GET /api/cpu` - Get CPU usage.
- `GET /api/memory` - Get memory usage.
- `GET /api/disk` - Get disk usage.

### Containers
- `GET /api/containers` - Get all containers with metrics and labels.

## Roadmap

- [ ] Able to save metrics to a database / filesystem in a time series format.

## License
Apache 2.0

