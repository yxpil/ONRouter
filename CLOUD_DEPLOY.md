# ONRouter Cloud Deployment Guide

This guide covers deploying ONRouter Gateway to various cloud platforms.

## Table of Contents
- [Docker](#docker)
- [Docker Compose](#docker-compose)
- [Kubernetes](#kubernetes)
- [AWS](#aws)
- [Azure](#azure)
- [Google Cloud](#google-cloud)

## Docker

### Build Image
```bash
docker build -t yxpil/onrouter:latest .
```

### Run Container
```bash
docker run -d \
  --name onrouter-gateway \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/conf:/app/conf:ro \
  -v $(pwd)/certs:/app/certs:ro \
  yxpil/onrouter:latest
```

## Docker Compose

### Quick Start
```bash
# Deploy
./deploy.sh deploy

# Or manually
docker-compose up -d

# View logs
docker-compose logs -f onrouter

# Stop
docker-compose down
```

### Configuration
Edit `conf/onrouter.conf` before deployment. See `conf/onrouter.conf.example` for reference.

## Kubernetes

### Deploy
```bash
# Apply configuration
kubectl apply -f kubernetes/deployment.yaml

# Check status
kubectl get pods -l app=onrouter
kubectl get svc onrouter-gateway

# View logs
kubectl logs -f deployment/onrouter-gateway
```

### Scale
```bash
kubectl scale deployment onrouter-gateway --replicas=5
```

### Update
```bash
kubectl set image deployment/onrouter-gateway onrouter=yxpil/onrouter:latest
kubectl rollout status deployment/onrouter-gateway
```

### Rollback
```bash
kubectl rollout undo deployment/onrouter-gateway
```

## AWS

### ECS (Elastic Container Service)

1. Push image to ECR:
```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker tag yxpil/onrouter:latest <account>.dkr.ecr.us-east-1.amazonaws.com/onrouter:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/onrouter:latest
```

2. Create task definition and service using AWS Console or CLI

### EKS (Elastic Kubernetes Service)
Use the Kubernetes deployment files above with your EKS cluster.

## Azure

### AKS (Azure Kubernetes Service)

1. Login to Azure:
```bash
az login
az aks get-credentials --resource-group myResourceGroup --name myAKSCluster
```

2. Deploy:
```bash
kubectl apply -f kubernetes/deployment.yaml
```

### Azure Container Instances
```bash
az container create \
  --resource-group myResourceGroup \
  --name onrouter-gateway \
  --image yxpil/onrouter:latest \
  --dns-name-label onrouter-gateway \
  --ports 80 443
```

## Google Cloud

### GKE (Google Kubernetes Engine)

1. Connect to cluster:
```bash
gcloud container clusters get-credentials onrouter-cluster --zone us-central1-a
```

2. Deploy:
```bash
kubectl apply -f kubernetes/deployment.yaml
```

### Cloud Run
```bash
gcloud run deploy onrouter-gateway \
  --image yxpil/onrouter:latest \
  --platform managed \
  --port 80 \
  --allow-unauthenticated
```

## Monitoring

### Prometheus Metrics
ONRouter exposes metrics at `/metrics` endpoint. Configure your monitoring solution to scrape this endpoint.

### Health Checks
- HTTP health check: `GET /health`
- Returns: `200 OK` when gateway is running

### Logging
All logs are written to `/app/logs/`:
- `access.log` - Request logs
- `error.log` - Error and warning logs

Configure log rotation in production environments.

## Security Best Practices

1. **TLS Certificates**: Mount certificates securely
   ```bash
   kubectl create secret tls onrouter-certs --cert=cert.pem --key=key.pem
   ```

2. **Non-root User**: The container runs as non-root user by default

3. **Network Policies**: Restrict ingress/egress traffic in Kubernetes

4. **Secrets Management**: Use Kubernetes Secrets or cloud-specific secret managers for sensitive data

5. **Resource Limits**: Always set CPU and memory limits to prevent resource exhaustion

## Troubleshooting

### Container won't start
```bash
docker logs onrouter-gateway
```

### Check configuration syntax
```bash
docker run --rm -v $(pwd)/conf:/app/conf:ro yxpil/onrouter:latest -t
```

### Kubernetes pod issues
```bash
kubectl describe pod <pod-name>
kubectl logs <pod-name>
```

## Support

For issues and feature requests, please visit:
https://github.com/yxpil/ONRouter/issues
