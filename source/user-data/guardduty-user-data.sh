sudo su
cat <<'EOF' >> /home/ec2-user/guardduty-script.sh

export PATH=$PATH:/usr/local/bin
tmp_dir=/home/ec2-user/tmp
region=us-east-1
cluster_name=$(aws ssm get-parameter --name security_demo_eks_name_parameter --region $region --output text --query Parameter.Value)

sudo yum update -y

# Install EKS and all dependencies
mkdir $tmp_dir
if [ ! -d $tmp_dir/.aws ];
then
    echo "$tmp_dir/.aws already exists." 
else
    mkdir $tmp_dir/.aws
fi
sudo curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C $tmp_dir
sleep 5
sudo mv $tmp_dir/eksctl /usr/local/bin

sudo curl -o $tmp_dir/kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.20.4/2021-04-12/bin/linux/amd64/kubectl 
sleep 5
sudo chmod +x $tmp_dir/kubectl
sudo mv $tmp_dir/kubectl /usr/local/bin/kubectl

aws ec2 create-key-pair --key-name guardduty-demo-key --region $region --tag-specifications 'ResourceType=key-pair,Tags=[{Key=security-demo,Value=true}]'
sleep 30

eksctl create cluster --name $cluster_name --region $region --with-oidc --ssh-access --ssh-public-key guardduty-demo-key --managed --tags security-demo=true >> /home/ec2-user/eks-deploy.log
sleep 60

if [[ $cluster_name == 1 ]]; then
then
  echo "$cluster_name cluster successfully created."
else
  var=("abcdef")
  zones=$region${var:$(( RANDOM % ${#var} )):1},$region${var:$(( RANDOM % ${#var} )):1},$region${var:$(( RANDOM % ${#var} )):1};
  eksctl create cluster --name $cluster_name --region $region --with-oidc --ssh-access --ssh-public-key guardduty-demo-key --managed --tags security-demo=true --zones $zones >> /home/ec2-user/eks-deploy1.log
  echo "$cluster_name cluster successfully created in $zones."
fi

sleep 60

aws eks update-kubeconfig --region $region --name $cluster_name

##### Create EKS findings

### Creating Kubernetes/ExposedDashboard

cat <<'EOT' >> $tmp_dir/k8s-dashboard.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kubernetes-dashboard

---

apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard

---

kind: Service
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  ports:
    - port: 443
      targetPort: 8443
  selector:
    k8s-app: kubernetes-dashboard

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-certs
  namespace: kubernetes-dashboard
type: Opaque

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-csrf
  namespace: kubernetes-dashboard
type: Opaque
data:
  csrf: ""

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-key-holder
  namespace: kubernetes-dashboard
type: Opaque

---

kind: ConfigMap
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-settings
  namespace: kubernetes-dashboard

---

kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
rules:
  # Allow Dashboard to get, update and delete Dashboard exclusive secrets.
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["kubernetes-dashboard-key-holder", "kubernetes-dashboard-certs", "kubernetes-dashboard-csrf"]
    verbs: ["get", "update", "delete"]
    # Allow Dashboard to get and update 'kubernetes-dashboard-settings' config map.
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["kubernetes-dashboard-settings"]
    verbs: ["get", "update"]
    # Allow Dashboard to get metrics.
  - apiGroups: [""]
    resources: ["services"]
    resourceNames: ["heapster", "dashboard-metrics-scraper"]
    verbs: ["proxy"]
  - apiGroups: [""]
    resources: ["services/proxy"]
    resourceNames: ["heapster", "http:heapster:", "https:heapster:", "dashboard-metrics-scraper", "http:dashboard-metrics-scraper"]
    verbs: ["get"]

---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
rules:
  # Allow Metrics Scraper to get metrics from the Metrics server
  - apiGroups: ["metrics.k8s.io"]
    resources: ["pods", "nodes"]
    verbs: ["get", "list", "watch"]

---

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubernetes-dashboard
subjects:
  - kind: ServiceAccount
    name: kubernetes-dashboard
    namespace: kubernetes-dashboard

---

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubernetes-dashboard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubernetes-dashboard
subjects:
  - kind: ServiceAccount
    name: kubernetes-dashboard
    namespace: kubernetes-dashboard

---

kind: Deployment
apiVersion: apps/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      k8s-app: kubernetes-dashboard
  template:
    metadata:
      labels:
        k8s-app: kubernetes-dashboard
    spec:
      containers:
        - name: kubernetes-dashboard
          image: kubernetesui/dashboard:v2.0.0
          imagePullPolicy: Always
          ports:
            - containerPort: 8443
              protocol: TCP
          args:
            - --enable-skip-login
            - --disable-settings-authorizer
            - --auto-generate-certificates
            - --namespace=kubernetes-dashboard
            # Uncomment the following line to manually specify Kubernetes API server Host
            # If not specified, Dashboard will attempt to auto discover the API server and connect
            # to it. Uncomment only if the default does not work.
            # - --apiserver-host=http://my-address:port
          volumeMounts:
            - name: kubernetes-dashboard-certs
              mountPath: /certs
              # Create on-disk volume to store exec logs
            - mountPath: /tmp
              name: tmp-volume
          livenessProbe:
            httpGet:
              scheme: HTTPS
              path: /
              port: 8443
            initialDelaySeconds: 30
            timeoutSeconds: 30
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsUser: 1001
            runAsGroup: 2001
      volumes:
        - name: kubernetes-dashboard-certs
          secret:
            secretName: kubernetes-dashboard-certs
        - name: tmp-volume
          emptyDir: {}
      serviceAccountName: kubernetes-dashboard
      nodeSelector:
        "kubernetes.io/os": linux
      # Comment the following tolerations if Dashboard must not be deployed on master
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule

---

kind: Service
apiVersion: v1
metadata:
  labels:
    k8s-app: dashboard-metrics-scraper
  name: dashboard-metrics-scraper
  namespace: kubernetes-dashboard
spec:
  ports:
    - port: 8000
      targetPort: 8000
  selector:
    k8s-app: dashboard-metrics-scraper

---

kind: Deployment
apiVersion: apps/v1
metadata:
  labels:
    k8s-app: dashboard-metrics-scraper
  name: dashboard-metrics-scraper
  namespace: kubernetes-dashboard
spec:
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      k8s-app: dashboard-metrics-scraper
  template:
    metadata:
      labels:
        k8s-app: dashboard-metrics-scraper
      annotations:
        seccomp.security.alpha.kubernetes.io/pod: 'runtime/default'
    spec:
      containers:
        - name: dashboard-metrics-scraper
          image: kubernetesui/metrics-scraper:v1.0.4
          ports:
            - containerPort: 8000
              protocol: TCP
          livenessProbe:
            httpGet:
              scheme: HTTP
              path: /
              port: 8000
            initialDelaySeconds: 30
            timeoutSeconds: 30
          volumeMounts:
          - mountPath: /tmp
            name: tmp-volume
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsUser: 1001
            runAsGroup: 2001
      serviceAccountName: kubernetes-dashboard
      nodeSelector:
        "kubernetes.io/os": linux
      # Comment the following tolerations if Dashboard must not be deployed on master
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      volumes:
        - name: tmp-volume
          emptyDir: {}
EOT

/usr/local/bin/kubectl apply -f $tmp_dir/k8s-dashboard.yaml


### Kubernetes/ExposedDashboard

cat <<'EOT' >> $tmp_dir/expose_k8s_dashboard.yaml
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard-lb
  namespace: kubernetes-dashboard
spec:
  type: LoadBalancer
  ports:
    - port: 443
      protocol: TCP
      targetPort: 8443
  selector:
    k8s-app: kubernetes-dashboard
EOT

/usr/local/bin/kubectl apply -f $tmp_dir/expose_k8s_dashboard.yaml

### Finding type: Policy:Kubernetes/AnonymousAccessGranted

cat <<'EOT' >> $tmp_dir/anonymous.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anonymous-admin
subjects:
  - kind: User
    name: system:anonymous
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOT

/usr/local/bin/kubectl apply -f $tmp_dir/anonymous.yaml

### Impact:Kubernetes/SuccessfulAnonymousAccess
### Discovery:Kubernetes/SuccessfulAnonymousAccess

CERT=`cat ~/.kube/config |grep certificate |cut -f2 -d: | sed 's/^ //'`
NAME=`cat ~/.kube/config  | grep "\- name:" |cut -f3 -d" "`
SERVER=`cat ~/.kube/config |grep "server:" |cut -f6 -d " "`

touch $tmp_dir/anonymous-kubeconfig
echo "apiVersion: v1">>$tmp_dir/anonymous-kubeconfig
echo "clusters:" >>$tmp_dir/anonymous-kubeconfig
echo "- cluster:" >>$tmp_dir/anonymous-kubeconfig
echo "    certificate-authority-data: $CERT" >>$tmp_dir/anonymous-kubeconfig
echo "    server: $SERVER" >>$tmp_dir/anonymous-kubeconfig
echo "  name: $NAME" >>$tmp_dir/anonymous-kubeconfig
echo "contexts:">>$tmp_dir/anonymous-kubeconfig
echo "- context:">>$tmp_dir/anonymous-kubeconfig
echo "    cluster: $NAME">>$tmp_dir/anonymous-kubeconfig
echo "    user: $NAME" >>$tmp_dir/anonymous-kubeconfig
echo "  name: $NAME" >>$tmp_dir/anonymous-kubeconfig
echo "current-context: $NAME" >>$tmp_dir/anonymous-kubeconfig
echo "kind: Config">>$tmp_dir/anonymous-kubeconfig
echo "preferences: {}">>$tmp_dir/anonymous-kubeconfig


###  Finding type: PrivilegeEscalation:Kubernetes/PrivilegedContainer
cat <<'EOT' >> $tmp_dir/priv-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: privileged-pod
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 2000
      allowPrivilegeEscalation: true
      privileged: true
EOT

/usr/local/bin/kubectl apply -f $tmp_dir/priv-pod.yaml

### Finding type: Policy:Kubernetes/AdminAccessToDefaultServiceAccount

cat <<'EOT' >> $tmp_dir/elevate.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: default-service-acct-admin
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOT

/usr/local/bin/kubectl apply -f $tmp_dir/elevate.yaml


###  Finding type: PrivilegeEscalation:Kubernetes/PrivilegedContainer
###  Finding type:Kubernetes/ContainerWithSensitiveMount Incident
          
cat <<'EOT' >> $tmp_dir/pod_with_sensitive_mount.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ubuntu-privileged-with-mount
spec:
  selector:
    matchLabels:
      app: ubuntu-privileged-with-mount
  replicas: 1
  template:
    metadata:
      labels:
        app: ubuntu-privileged-with-mount
    spec:
      containers:
      - name: ubuntu-privileged-with-mount
        image: nginx
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /test-pd
          name: test-volume
      volumes:
      - name: test-volume
        hostPath:
          path: /etc
          type: Directory
EOT

/usr/local/bin/kubectl apply -f $tmp_dir/pod_with_sensitive_mount.yaml 

### Finding type: Execution:Kubernetes/ExecInKubeSystemPod

/usr/local/bin/kubectl run --image=nginx restricted-namespace-pod -n kube-system
sleep 10

POD_ID=`/usr/local/bin/kubectl get pod -n kube-system | grep "restricted-namespace-pod" | cut -f1 -d " "`
/usr/local/bin/kubectl exec -it $POD_ID sh -n kube-system <<'EOT'
date
EOT

EOF

sudo chmod 744 /home/ec2-user/guardduty-script.sh
chown ec2-user /home/ec2-user/guardduty-script.sh
echo "* * * * * /home/ec2-user/guardduty-script.sh > /home/ec2-user/guardduty-script.log 2>&1" | tee -a /var/spool/cron/ec2-user
sudo /home/ec2-user/guardduty-script.sh