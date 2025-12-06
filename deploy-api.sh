#!/bin/bash

# Quantok Scanner API - Manual Build & Deploy Script
# Run this script to build and deploy to Cloud Run

set -e

PROJECT_ID="quantoktslx"
REGION="us-central1"
REPO="tlsx-api"
SERVICE_NAME="quantok-scanner"
IMAGE_NAME="us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO}/${SERVICE_NAME}:latest"

echo "=========================================="
echo "Quantok Scanner API - Build & Deploy"
echo "=========================================="
echo ""

# Step 1: Build the Docker image
echo "Step 1/4: Building Docker image..."
docker build -t ${IMAGE_NAME} -f Dockerfile.api .
echo "✓ Image built successfully"
echo ""

# Step 2: Configure Docker for Artifact Registry and push
echo "Step 2/4: Pushing to Artifact Registry..."
gcloud auth configure-docker us-central1-docker.pkg.dev --quiet
docker push ${IMAGE_NAME}
echo "✓ Image pushed successfully"
echo ""

# Step 3: Deploy to Cloud Run
echo "Step 3/4: Deploying to Cloud Run..."
gcloud run deploy ${SERVICE_NAME} \
  --image ${IMAGE_NAME} \
  --region ${REGION} \
  --allow-unauthenticated \
  --port 8080 \
  --max-instances 10 \
  --cpu 1 \
  --memory 512Mi \
  --quiet
echo "✓ Deployed successfully"
echo ""

# Step 4: Get the service URL
echo "Step 4/4: Getting service URL..."
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} --region ${REGION} --format="value(status.url)")
echo "✓ Service URL: ${SERVICE_URL}"
echo ""

echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
echo ""
echo "Test your API:"
echo "curl ${SERVICE_URL}/health"
echo ""
echo "Run a scan:"
echo "curl -X POST ${SERVICE_URL}/api/v1/scan \\"
echo "  -H 'Content-Type: application/json' \\"
echo "  -d '{\"target\":\"google.com\"}'"
echo ""
