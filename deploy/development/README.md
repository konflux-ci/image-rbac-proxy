Deploy it in a local Konflux created by https://github.com/konflux-ci/konflux-ci.

Update kind-config.yaml in konflux-ci:
```
+ networking:
+  apiServerAddress: IP
+  apiServerPort: 6443

+    # image-rbac-proxy
+  - containerPort: 30013
+    hostPort: 443
+    protocol: TCP
+    # image-proxy-dex
+  - containerPort: 30014
+    hostPort: 8443
+    protocol: TCP
```
Update secret.yaml, configmap.yaml and IP with configs for testing.

Deploy proxy:
```
$ kubectl kustomize . > deploy-all.yaml
$ kubectl apply -f deploy-all.yaml
```
Create dex client secret:
```
$ client_secret="$(openssl rand -base64 20 | tr '+/' '-_' | tr -d '\n' | tr -d '=')"
$ kubectl create secret generic image-proxy-client-secret \
        --namespace=image-rbac-proxy \
        --from-literal=client-secret="$client_secret"
```
Add dex CA and cluster CA to trusted-ca:
```
kubectl edit secret -n cert-manager root-secret
```
