#!/bin/bash
set -e

# ONRouter Gateway Deployment Script
# Supports: Docker, Docker Compose, Kubernetes

COLOR_GREEN='\033[0;32m'
COLOR_BLUE='\033[0;34m'
COLOR_RED='\033[0;31m'
NC='\033[0m' # No Color

VERSION="0.2.0"
IMAGE_NAME="yxpil/onrouter"

usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  build          Build Docker image"
    echo "  push           Push image to registry"
    echo "  deploy         Deploy with Docker Compose"
    echo "  k8s-deploy     Deploy to Kubernetes"
    echo "  stop           Stop deployment"
    echo "  logs           View logs"
    echo "  status         Check status"
    echo ""
    echo "Options:"
    echo "  -v, --version  Specify version (default: $VERSION)"
    echo "  -h, --help     Show this help"
    exit 1
}

log_info() {
    echo -e "${COLOR_BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${COLOR_RED}[ERROR]${NC} $1"
}

build_image() {
    log_info "Building ONRouter Docker image v$VERSION..."
    docker build -t ${IMAGE_NAME}:${VERSION} .
    docker tag ${IMAGE_NAME}:${VERSION} ${IMAGE_NAME}:latest
    log_success "Image built successfully: ${IMAGE_NAME}:${VERSION}"
}

push_image() {
    log_info "Pushing image to registry..."
    docker push ${IMAGE_NAME}:${VERSION}
    docker push ${IMAGE_NAME}:latest
    log_success "Image pushed successfully"
}

deploy_compose() {
    log_info "Deploying with Docker Compose..."
    
    # Create conf directory if not exists
    mkdir -p conf certs
    
    # Check if config exists
    if [ ! -f conf/onrouter.conf ]; then
        log_info "Creating default configuration..."
        cat > conf/onrouter.conf << 'EOF'
worker_connections 10240;

events {
    worker_connections 10240;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    
    keepalive_timeout 65;
    keepalive_requests 1000;
    
    client_max_body_size 10m;
    
    error_log /app/logs/error.log warn;
    access_log /app/logs/access.log;
    
    server {
        listen 80;
        server_name localhost;
        
        location / {
            return 200 'ONRouter Gateway is running!';
            add_header Content-Type text/plain;
        }
        
        location /health {
            return 200 'OK';
            add_header Content-Type text/plain;
        }
    }
}
EOF
        log_success "Default configuration created at conf/onrouter.conf"
    fi
    
    docker-compose up -d
    log_success "Deployment completed"
}

deploy_kubernetes() {
    log_info "Deploying to Kubernetes..."
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi
    
    kubectl apply -f kubernetes/deployment.yaml
    log_success "Kubernetes deployment applied"
    
    log_info "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=onrouter --timeout=120s
    log_success "All pods are ready"
}

stop_deployment() {
    log_info "Stopping deployment..."
    
    if docker-compose ps &> /dev/null; then
        docker-compose down
    fi
    
    log_success "Deployment stopped"
}

view_logs() {
    docker-compose logs -f onrouter
}

check_status() {
    echo "=== ONRouter Gateway Status ==="
    echo ""
    
    if docker-compose ps &> /dev/null; then
        echo "Docker Compose Services:"
        docker-compose ps
        echo ""
    fi
    
    if command -v kubectl &> /dev/null; then
        echo "Kubernetes Pods:"
        kubectl get pods -l app=onrouter 2>/dev/null || echo "No Kubernetes deployment found"
        echo ""
    fi
    
    echo "Local Processes:"
    ps aux | grep onrouter | grep -v grep || echo "No local processes running"
}

# Parse arguments
COMMAND=""
while [[ $# -gt 0 ]]; do
    case $1 in
        build|push|deploy|k8s-deploy|stop|logs|status|-h|--help)
            COMMAND=$1
            shift
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

if [ -z "$COMMAND" ]; then
    usage
fi

case $COMMAND in
    build)
        build_image
        ;;
    push)
        push_image
        ;;
    deploy)
        deploy_compose
        ;;
    k8s-deploy)
        deploy_kubernetes
        ;;
    stop)
        stop_deployment
        ;;
    logs)
        view_logs
        ;;
    status)
        check_status
        ;;
    -h|--help)
        usage
        ;;
esac
