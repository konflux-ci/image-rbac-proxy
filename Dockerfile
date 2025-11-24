FROM registry.access.redhat.com/ubi10/go-toolset:latest
COPY . .
LABEL name="Konflux Image RBAC Proxy"
LABEL description="Konflux Image RBAC Proxy"
LABEL io.k8s.description="Konflux Image RBAC Proxy"
LABEL io.k8s.display-name="image-rbac-proxy"
LABEL io.openshift.tags="konflux"
LABEL summary="Konflux Image RBAC Proxy"
LABEL com.redhat.component="image-rbac-proxy"
RUN go build -buildvcs=false
CMD ["/opt/app-root/src/image-rbac-proxy"]
