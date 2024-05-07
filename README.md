# Sentinel

An experimental API for gathering Linux server / Docker Engine metrics.

> Will be use by [coolify.io](https://coolify.io).

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
docker run -d -p 127.0.0.1:8888:8888 -v /var/run/docker.sock:/var/run/docker.sock --name sentinel ghcr.io/coollabsio/sentinel:latest
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
MIT

