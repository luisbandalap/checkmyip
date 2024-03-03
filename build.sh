# Set your manifest name
export MANIFEST_NAME="checkmyip-multiarch"

# Set the required variables
export BUILD_PATH="."
export REGISTRY="docker.io"
export USER="luisbandalap"
export IMAGE_NAME="checkmyip"
export IMAGE_TAG="`date -u +"%Y%m%d"`"
export LABEL_CREATE_DATE="`date -u +"%Y-%m-%dT%H:%M:%SZ"`"
export LABEL_AUTHOR="luisbandalap <luis449bp+checkmyip@gmail.com>"
export LABEL_DESCRIPTION="A Telnet, SSH and Simple HTTP Based Public IP Address Lookup Service"
export LABEL_VENDOR="luisbandalap"
export LABEL_SOURCE_URL="https://github.com/luisbandalap/checkmyip"
export LABEL_TITLE="CheckMyIP (TelnetMyIP.com)"
export BUILDAH_FORMAT=docker

# Create a multi-architecture manifest
buildah manifest rm ${MANIFEST_NAME}
buildah manifest create ${MANIFEST_NAME}

# Create images for all specified architectures
for IMAGE_ARCH in amd64 arm64 arm; do \
    buildah build \
        --tag "${REGISTRY}/${USER}/${IMAGE_NAME}:${IMAGE_TAG}" \
        --tag "${REGISTRY}/${USER}/${IMAGE_NAME}:latest" \
        --label "org.opencontainers.image.authors=${LABEL_AUTHOR}" \
        --label "org.opencontainers.image.created=${LABEL_CREATE_DATE}" \
        --label "org.opencontainers.image.description=${LABEL_DESCRIPTION}" \
        --label "org.opencontainers.image.source=${LABEL_SOURCE_URL}" \
        --label "org.opencontainers.image.title=${LABEL_TITLE}" \
        --label "org.opencontainers.image.url=${LABEL_SOURCE_URL}" \
        --label "org.opencontainers.image.vendor=${LABEL_VENDOR}" \
        --label "org.opencontainers.image.version=${IMAGE_TAG}" \
        --format=docker \
        --manifest ${MANIFEST_NAME} \
        --arch ${IMAGE_ARCH} \
        ${BUILD_PATH}; \
done

# Push the full manifest, with both CPU Architectures
for CURRENT_TAG in ${IMAGE_TAG} latest; do \
    buildah manifest push --all \
        ${MANIFEST_NAME} \
        "docker://${REGISTRY}/${USER}/${IMAGE_NAME}:${CURRENT_TAG}"; \
done
