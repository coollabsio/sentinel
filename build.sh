#!/bin/bash

# Sentinel Docker Build Script
# Quick build script for building Docker images locally

set -e  # Exit on error

# Default image name and tag
IMAGE_NAME="${IMAGE_NAME:-sentinel}"
TAG="${TAG:-local}"

echo "🐳 Building Docker image: ${IMAGE_NAME}:${TAG}"
echo ""

# Build the Docker image
docker build -t "${IMAGE_NAME}:${TAG}" .

echo ""
echo "✅ Docker image built successfully!"
echo ""
echo "Image: ${IMAGE_NAME}:${TAG}"
echo ""
echo "To run:"
echo "  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ${IMAGE_NAME}:${TAG}"
echo ""
echo "To customize image name/tag:"
echo "  IMAGE_NAME=myname TAG=v1.0 ./build.sh"
