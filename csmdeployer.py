#! /usr/bin/env python3
import os
import sys
import textwrap
import time
import yaml

from base import Base
class Exchange:
    def __init__(self, logger):
        self.base = Base(logger)
        self.logger = logger

    def update_images_from_config(self):
        try:
            image_file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/image.yaml"
            
            if os.path.exists(image_file_path):
                with open(image_file_path, 'r') as image_file:
                    image_data = yaml.safe_load(image_file)
                    
                    if 'image' in image_data:
                        images = image_data['image']
                        
                        # 判断是否为空值或是否存在相应的镜像版本，如果存在版本号，则更新对应的 Kubernetes 部署
                        if images.get('ks-console'):
                            self.set_image_deployment('ks-console', images['ks-console'], 'kubesphere-system')

                        if images.get('ks-apiserver'):
                            self.set_image_deployment('ks-apiserver', images['ks-apiserver'], 'kubesphere-system')

                        if images.get('ks-controller-manager'):
                            self.set_image_deployment('ks-controller-manager', images['ks-controller-manager'], 'kubesphere-system')

                        if images.get('default-http-backend'):
                            self.set_image_deployment('default-http-backend', images['default-http-backend'], 'kubesphere-controls-system')

                        if images.get('kubectl-admin'):
                            self.set_image_deployment('kubectl-admin', images['kubectl-admin'], 'kubesphere-controls-system')
                    else:
                        print("image.yaml 配置文件中未找到镜像部分，程序终止")
                        sys.exit()
            else:
                print("未找到 image.yaml 配置文件，程序终止")
                sys.exit()

            return True
        except Exception as e:
            print(f"更新镜像版本时发生错误：{e}")
            self.logger.log(f"更新镜像版本时发生错误：{e}")  # debug
            return False

    def set_image_deployment(self, deployment_name, image_version_in_config, namespace):
        if image_version_in_config:
            command = f"kubectl set image deployment {deployment_name} {deployment_name}={image_version_in_config} -n {namespace}"
            result = self.base.com(command).stdout
            if "not found" in result:
                print(f"找不到 {deployment_name}的 image 版本, 请查看日志检查问题")
            else:
                print(f"{deployment_name} image 版本更新为 {image_version_in_config}，更新完成")
            
    # def default_execution(self):
    #     command = '''
    #     kubectl set image deployment ks-console ks-console=feixitek/cosan-console:v1.0.5-ppc64 -n kubesphere-system
    #     kubectl set image deployment ks-apiserver ks-apiserver=feixitek/vtel-server:v1.0.4-ppc64 -n kubesphere-system
    #     kubectl set image deployment ks-controller-manager ks-controller-manager=feixitek/kscontrolmanagerppc64le:1.0 -n kubesphere-system
    #     kubectl set image deployment default-http-backend default-http-backend=ibmcom/defaultbackend:1.5 -n kubesphere-controls-system
    #     kubectl set image deployment kubectl-admin kubectl=feixitek/kubectl-ppc64le:1.20.4 -n kubesphere-controls-system
    #     '''
    #     self.base.com(command)

class Csmdeployer:
    def __init__(self, logger):
        self.base = Base(logger)
        self.logger = logger
        self.spec = None
        self.controller_ip = None
        self.kubernetes_control_endpoint = None
        self.check_controller_ip()

    # 检测 配置文件里有没有 controller_ip 
    def check_controller_ip(self):
        # 从 csmdeployer_config.yaml 中读取特定内容
        config_file = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/csmdeployer_config.yaml"
        if os.path.exists(config_file):
            with open(config_file, 'r') as cfg:
                config_data = yaml.safe_load(cfg)
            if config_data and 'vsds_controller_ip' in config_data:
                custom_controller_ip = config_data['vsds_controller_ip']
                if custom_controller_ip:
                    self.controller_ip = custom_controller_ip
                else:
                    print("csmdeployer_config.yaml 配置文件中 vsds_controller_ip 部分为空！")
                    sys.exit()
            else:
                print("csmdeployer_config.yaml 配置文件中未找到有效的 vsds_controller_ip 部分")
                sys.exit()
            if config_data and 'kubernetes_control_endpoint' in config_data and config_data['kubernetes_control_endpoint']:
                self.kubernetes_control_endpoint = config_data['kubernetes_control_endpoint']
            else:
                print("kubernetes_control_endpoint 配置错误，请检查")
                sys.exit()

            if config_data and 'spec' in config_data and config_data['spec']:
                self.spec = config_data['spec']
        else:
            print("未找到 csmdeployer_config.yaml 配置文件。请检查 csmdeployer_config.yaml文件是否存在。")
            sys.exit()

    # 初始化 Kubernetes 集群
    def initialising_kubernetes_cluster(self):
        try:
            command = f"kubeadm init --kubernetes-version=v1.20.5 --image-repository registry.aliyuncs.com/google_containers --pod-network-cidr=10.244.0.0/16 --control-plane-endpoint {self.kubernetes_control_endpoint}:6443 --apiserver-advertise-address {self.kubernetes_control_endpoint} --upload-certs"
            result = self.base.com(command).stdout
            # 做操作
            

            return True
        except Exception as e:
            print(f"初始化 Kubernetes 集群发生错误：{e}")
            self.logger.log(f"初始化 Kubernetes 集群发生错误：{e}")  # debug
            return False

    # 配置 kubectl 工具
    def configure_kubectl_tool(self):  
        try:
            # 执行命令
            command = '''
            mkdir -p $HOME/.kube
            cp /etc/kubernetes/admin.conf /root/.kube/config
            '''
            self.base.com(command)

            return True
        except Exception as e:
            print(f"配置 kubectl 工具发生错误：{e}")
            self.logger.log(f"配置 kubectl 工具发生错误：{e}")  # debug
            return False

    # 配置网络
    def configure_net(self):

        try:
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/flannel.yaml"
            self.logger.log(f"在控制节点创建 flannel.yaml 文件：{file_path}")
            flannel_config = textwrap.dedent('''
---
kind: Namespace
apiVersion: v1
metadata:
  name: kube-flannel
  labels:
    k8s-app: flannel
    pod-security.kubernetes.io/enforce: privileged
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: flannel
  name: flannel
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - nodes/status
  verbs:
  - patch
- apiGroups:
  - networking.k8s.io
  resources:
  - clustercidrs
  verbs:
  - list
  - watch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: flannel
  name: flannel
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: flannel
subjects:
- kind: ServiceAccount
  name: flannel
  namespace: kube-flannel
---
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: flannel
  name: flannel
  namespace: kube-flannel
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: kube-flannel-cfg
  namespace: kube-flannel
  labels:
    tier: node
    k8s-app: flannel
    app: flannel
data:
  cni-conf.json: |
    {
      "name": "cbr0",
      "cniVersion": "0.3.1",
      "plugins": [
        {
          "type": "flannel",
          "delegate": {
            "hairpinMode": true,
            "isDefaultGateway": true
          }
        },
        {
          "type": "portmap",
          "capabilities": {
            "portMappings": true
          }
        }
      ]
    }
  net-conf.json: |
    {
      "Network": "10.244.0.0/16",
      "Backend": {
        "Type": "vxlan"
      }
    }
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-flannel-ds
  namespace: kube-flannel
  labels:
    tier: node
    app: flannel
    k8s-app: flannel
spec:
  selector:
    matchLabels:
      app: flannel
  template:
    metadata:
      labels:
        tier: node
        app: flannel
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/os
                operator: In
                values:
                - linux
      hostNetwork: true
      priorityClassName: system-node-critical
      tolerations:
      - operator: Exists
        effect: NoSchedule
      serviceAccountName: flannel
      initContainers:
      - name: install-cni-plugin
        image: docker.io/flannel/flannel-cni-plugin:v1.1.2
        command:
        - cp
        args:
        - -f
        - /flannel
        - /opt/cni/bin/flannel
        volumeMounts:
        - name: cni-plugin
          mountPath: /opt/cni/bin
      - name: install-cni
        image: docker.io/flannel/flannel:v0.22.0
        command:
        - cp
        args:
        - -f
        - /etc/kube-flannel/cni-conf.json
        - /etc/cni/net.d/10-flannel.conflist
        volumeMounts:
        - name: cni
          mountPath: /etc/cni/net.d
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      containers:
      - name: kube-flannel
        image: docker.io/flannel/flannel:v0.22.0
        command:
        - /opt/bin/flanneld
        args:
        - --ip-masq
        - --kube-subnet-mgr
        resources:
          requests:
            cpu: "100m"
            memory: "50Mi"
        securityContext:
          privileged: false
          capabilities:
            add: ["NET_ADMIN", "NET_RAW"]
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: EVENT_QUEUE_DEPTH
          value: "5000"
        volumeMounts:
        - name: run
          mountPath: /run/flannel
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
        - name: xtables-lock
          mountPath: /run/xtables.lock
      volumes:
      - name: run
        hostPath:
          path: /run/flannel
      - name: cni-plugin
        hostPath:
          path: /opt/cni/bin
      - name: cni
        hostPath:
          path: /etc/cni/net.d
      - name: flannel-cfg
        configMap:
          name: kube-flannel-cfg
      - name: xtables-lock
        hostPath:
          path: /run/xtables.lock
          type: FileOrCreate
            ''')
            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(flannel_config)

            # 执行部署
            command = "kubectl apply -f flannel.yaml"
            self.base.com(command)

            return True
        except Exception as e:
            print(f"配置网络发生错误：{e}")
            self.logger.log(f"配置网络发生错误：{e}")  # debug
            return False
    
    # 配置 controller 节点以可以运行 pod
    def configure_controller(self):
        try:
            # 执行命令
            command = "kubectl taint nodes --all node-role.kubernetes.io/master-"
            self.base.com(command)

            return True
        except Exception as e:
            print(f"配置 controller 节点发生错误：{e}")
            self.logger.log(f"配置 controller 节点发生错误：{e}")  # debug
            return False
        
    # 配置默认 storageclass
    def configure_storageclass(self):
        try:
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/openebsc.yaml"
            self.logger.log(f"在控制节点创建 openebsc.yaml 文件：{file_path}")
            openebsc_config = textwrap.dedent('''
---
#Sample storage classes for OpenEBS Local PV
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local
  annotations:
    storageclass.kubesphere.io/supported-access-modes: '["ReadWriteOnce"]'
    storageclass.beta.kubernetes.io/is-default-class: "true"
    openebs.io/cas-type: local
    cas.openebs.io/config: |
      - name: StorageType
        value: "hostpath"
      - name: BasePath
        value: "/var/openebs/local/"
provisioner: openebs.io/local
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete
---
# Create Maya Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: openebs-maya-operator
  namespace: kube-system
---
# Define Role that allows operations on K8s pods/deployments
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: openebs-maya-operator
rules:
- apiGroups: ["*"]
  resources: ["nodes", "nodes/proxy"]
  verbs: ["*"]
- apiGroups: ["*"]
  resources: ["namespaces", "services", "pods", "pods/exec", "deployments", "deployments/finalizers", "replicationcontrollers", "replicasets", "events", "endpoints", "configmaps", "secrets", "jobs", "cronjobs"]
  verbs: ["*"]
- apiGroups: ["*"]
  resources: ["statefulsets", "daemonsets"]
  verbs: ["*"]
- apiGroups: ["*"]
  resources: ["resourcequotas", "limitranges"]
  verbs: ["list", "watch"]
- apiGroups: ["*"]
  resources: ["ingresses", "horizontalpodautoscalers", "verticalpodautoscalers", "poddisruptionbudgets", "certificatesigningrequests"]
  verbs: ["list", "watch"]
- apiGroups: ["*"]
  resources: ["storageclasses", "persistentvolumeclaims", "persistentvolumes"]
  verbs: ["*"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: [ "get", "list", "create", "update", "delete", "patch"]
- apiGroups: ["openebs.io"]
  resources: [ "*"]
  verbs: ["*"]
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
# Bind the Service Account with the Role Privileges.
# TODO: Check if default account also needs to be there
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: openebs-maya-operator
subjects:
- kind: ServiceAccount
  name: openebs-maya-operator
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: openebs-maya-operator
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openebs-localpv-provisioner
  namespace: kube-system
  labels:
    name: openebs-localpv-provisioner
    openebs.io/component-name: openebs-localpv-provisioner
    openebs.io/version: 3.3.0
spec:
  selector:
    matchLabels:
      name: openebs-localpv-provisioner
      openebs.io/component-name: openebs-localpv-provisioner
  replicas: 1
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        name: openebs-localpv-provisioner
        openebs.io/component-name: openebs-localpv-provisioner
        openebs.io/version: 3.3.0
    spec:
      serviceAccountName: openebs-maya-operator
      containers:
      - name: openebs-provisioner-hostpath
        imagePullPolicy: Always
        image: openebs/provisioner-localpv:3.3.0
        env:
        # OPENEBS_IO_K8S_MASTER enables openebs provisioner to connect to K8s
        # based on this address. This is ignored if empty.
        # This is supported for openebs provisioner version 0.5.2 onwards
        #- name: OPENEBS_IO_K8S_MASTER
        #  value: "<http://10.128.0.12:8080">
        # OPENEBS_IO_KUBE_CONFIG enables openebs provisioner to connect to K8s
        # based on this config. This is ignored if empty.
        # This is supported for openebs provisioner version 0.5.2 onwards
        #- name: OPENEBS_IO_KUBE_CONFIG
        #  value: "/home/ubuntu/.kube/config"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: OPENEBS_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        # OPENEBS_SERVICE_ACCOUNT provides the service account of this pod as
        # environment variable
        - name: OPENEBS_SERVICE_ACCOUNT
          valueFrom:
            fieldRef:
              fieldPath: spec.serviceAccountName
        - name: OPENEBS_IO_ENABLE_ANALYTICS
          value: "true"
        - name: OPENEBS_IO_INSTALLER_TYPE
          value: "openebs-operator-lite"
        - name: OPENEBS_IO_HELPER_IMAGE
          value: "openebs/linux-utils:3.3.0"
        # LEADER_ELECTION_ENABLED is used to enable/disable leader election. By default
        # leader election is enabled.
        #- name: LEADER_ELECTION_ENABLED
        #  value: "true"
        # OPENEBS_IO_IMAGE_PULL_SECRETS environment variable is used to pass the image pull secrets
        # to the helper pod launched by local-pv hostpath provisioner
        #- name: OPENEBS_IO_IMAGE_PULL_SECRETS
        #  value: ""
        livenessProbe:
          exec:
            command:
            - sh
            - -c
            - test $(pgrep -c "^provisioner-loc.*") = 1
          initialDelaySeconds: 30
          periodSeconds: 60
            ''')

            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(openebsc_config)

            # 执行部署
            command = "kubectl apply -f openebsc.yaml"
            self.base.com(command)

            return True
        except Exception as e:
            print(f"配置默认 storageclass发生错误：{e}")
            self.logger.log(f"配置默认 storageclass发生错误：{e}")  # debug
            return False
        
    # 初始化 CoSAN Manager
    def initialising_cosan_manager(self):
        try:
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/ks-installer.yaml"
            self.logger.log(f"在控制节点创建 ks-installer.yaml 文件：{file_path}")
            ks_installer = textwrap.dedent('''
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clusterconfigurations.installer.kubesphere.io
spec:
  group: installer.kubesphere.io
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              x-kubernetes-preserve-unknown-fields: true
            status:
              type: object
              x-kubernetes-preserve-unknown-fields: true
  scope: Namespaced
  names:
    plural: clusterconfigurations
    singular: clusterconfiguration
    kind: ClusterConfiguration
    shortNames:
      - cc

---
apiVersion: v1
kind: Namespace
metadata:
  name: kubesphere-system

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ks-installer
  namespace: kubesphere-system

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ks-installer
rules:
- apiGroups:
  - ""
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apps
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - extensions
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - batch
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apiregistration.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - tenant.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - certificates.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - devops.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - monitoring.coreos.com
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - logging.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - jaegertracing.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - storage.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - admissionregistration.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - policy
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - autoscaling
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - networking.istio.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - config.istio.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - iam.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - notification.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - auditing.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - events.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - core.kubefed.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - installer.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - storage.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - security.istio.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - monitoring.kiali.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - kiali.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - networking.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - edgeruntime.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - types.kubefed.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - monitoring.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - application.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'


---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: ks-installer
subjects:
- kind: ServiceAccount
  name: ks-installer
  namespace: kubesphere-system
roleRef:
  kind: ClusterRole
  name: ks-installer
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ks-installer
  namespace: kubesphere-system
  labels:
    app: ks-installer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ks-installer
  template:
    metadata:
      labels:
        app: ks-installer
    spec:
      serviceAccountName: ks-installer
      containers:
      - name: installer
        image: feixitek/ks-installer-complete332ppc64le:3.0
        imagePullPolicy: "IfNotPresent"
        resources:
          limits:
            cpu: "1"
            memory: 1Gi
          requests:
            cpu: 20m
            memory: 100Mi
        volumeMounts:
        - mountPath: /etc/localtime
          name: host-time
          readOnly: true
      volumes:
      - hostPath:
          path: /etc/localtime
          type: ""
        name: host-time
            ''')
            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(ks_installer)

            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/cluster-config.yaml"
            self.logger.log(f"在控制节点创建 cluster-config.yaml 文件：{file_path}")
            cluster_config = textwrap.dedent('''
---
apiVersion: installer.kubesphere.io/v1alpha1
kind: ClusterConfiguration
metadata:
  name: ks-installer
  namespace: kubesphere-system
  labels:
    version: v3.3.2
spec:
  persistence:
    storageClass: ""        # If there is no default StorageClass in your cluster, you need to specify an existing StorageClass here.
  authentication:
    # adminPassword: ""     # Custom password of the admin user. If the parameter exists but the value is empty, a random password is generated. If the parameter does not exist, P@88w0rd is used.
    jwtSecret: ""           # Keep the jwtSecret consistent with the Host Cluster. Retrieve the jwtSecret by executing "kubectl -n kubesphere-system get cm kubesphere-config -o yaml | grep -v "apiVersion" | grep jwtSecret" on the Host Cluster.
  local_registry: ""        # Add your private registry address if it is needed.
  # dev_tag: ""               # Add your kubesphere image tag you want to install, by default it's same as ks-installer release version.
  etcd:
    monitoring: false       # Enable or disable etcd monitoring dashboard installation. You have to create a Secret for etcd before you enable it.
    endpointIps: localhost  # etcd cluster EndpointIps. It can be a bunch of IPs here.
    port: 2379              # etcd port.
    tlsEnable: true
  common:
    core:
      console:
        enableMultiLogin: true  # Enable or disable simultaneous logins. It allows different users to log in with the same account at the same time.
        port: 30880
        type: NodePort

    # apiserver:            # Enlarge the apiserver and controller manager's resource requests and limits for the large cluster
    #  resources: {}
    # controllerManager:
    #  resources: {}
    redis:
      enabled: false
      enableHA: false
      volumeSize: 2Gi # Redis PVC size.
    openldap:
      enabled: false
      volumeSize: 2Gi   # openldap PVC size.
    minio:
      volumeSize: 20Gi # Minio PVC size.
    monitoring:
      # type: external   # Whether to specify the external prometheus stack, and need to modify the endpoint at the next line.
      endpoint: http://prometheus-operated.kubesphere-monitoring-system.svc:9090 # Prometheus endpoint to get metrics data.
      GPUMonitoring:     # Enable or disable the GPU-related metrics. If you enable this switch but have no GPU resources, Kubesphere will set it to zero.
        enabled: false
    gpu:                 # Install GPUKinds. The default GPU kind is nvidia.com/gpu. Other GPU kinds can be added here according to your needs.
      kinds:
      - resourceName: "nvidia.com/gpu"
        resourceType: "GPU"
        default: true
    es:   # Storage backend for logging, events and auditing.
      # master:
      #   volumeSize: 4Gi  # The volume size of Elasticsearch master nodes.
      #   replicas: 1      # The total number of master nodes. Even numbers are not allowed.
      #   resources: {}
      # data:
      #   volumeSize: 20Gi  # The volume size of Elasticsearch data nodes.
      #   replicas: 1       # The total number of data nodes.
      #   resources: {}
      logMaxAge: 7             # Log retention time in built-in Elasticsearch. It is 7 days by default.
      elkPrefix: logstash      # The string making up index names. The index name will be formatted as ks-<elk_prefix>-log.
      basicAuth:
        enabled: false
        username: ""
        password: ""
      externalElasticsearchHost: ""
      externalElasticsearchPort: ""
  alerting:                # (CPU: 0.1 Core, Memory: 100 MiB) It enables users to customize alerting policies to send messages to receivers in time with different time intervals and alerting levels to choose from.
    enabled: true        # Enable or disable the KubeSphere Alerting System.
    # thanosruler:
    #   replicas: 1
    #   resources: {}
  auditing:                # Provide a security-relevant chronological set of records，recording the sequence of activities happening on the platform, initiated by different tenants.
    enabled: false         # Enable or disable the KubeSphere Auditing Log System.
    # operator:
    #   resources: {}
    # webhook:
    #   resources: {}
  devops:                  # (CPU: 0.47 Core, Memory: 8.6 G) Provide an out-of-the-box CI/CD system based on Jenkins, and automated workflow tools including Source-to-Image & Binary-to-Image.
    enabled: false             # Enable or disable the KubeSphere DevOps System.
    # resources: {}
    jenkinsMemoryLim: 4Gi      # Jenkins memory limit.
    jenkinsMemoryReq: 2Gi   # Jenkins memory request.
    jenkinsVolumeSize: 8Gi     # Jenkins volume size.
  events:                  # Provide a graphical web console for Kubernetes Events exporting, filtering and alerting in multi-tenant Kubernetes clusters.
    enabled: false         # Enable or disable the KubeSphere Events System.
    # operator:
    #   resources: {}
    # exporter:
    #   resources: {}
    # ruler:
    #   enabled: true
    #   replicas: 2
    #   resources: {}
  logging:                 # (CPU: 57 m, Memory: 2.76 G) Flexible logging functions are provided for log query, collection and management in a unified console. Additional log collectors can be added, such as Elasticsearch, Kafka and Fluentd.
    enabled: false         # Enable or disable the KubeSphere Logging System.
    logsidecar:
      enabled: true
      replicas: 2
      # resources: {}
  metrics_server:                    # (CPU: 56 m, Memory: 44.35 MiB) It enables HPA (Horizontal Pod Autoscaler).
    enabled: false                   # Enable or disable metrics-server.
  monitoring:
    storageClass: ""                 # If there is an independent StorageClass you need for Prometheus, you can specify it here. The default StorageClass is used by default.
    node_exporter:
      port: 9100
      # resources: {}
    # kube_rbac_proxy:
    #   resources: {}
    # kube_state_metrics:
    #   resources: {}
    # prometheus:
    #   replicas: 1  # Prometheus replicas are responsible for monitoring different segments of data source and providing high availability.
    #   volumeSize: 20Gi  # Prometheus PVC size.
    #   resources: {}
    #   operator:
    #     resources: {}
    # alertmanager:
    #   replicas: 1          # AlertManager Replicas.
    #   resources: {}
    # notification_manager:
    #   resources: {}
    #   operator:
    #     resources: {}
    #   proxy:
    #     resources: {}
    gpu:                           # GPU monitoring-related plug-in installation.
      nvidia_dcgm_exporter:        # Ensure that gpu resources on your hosts can be used normally, otherwise this plug-in will not work properly.
        enabled: false             # Check whether the labels on the GPU hosts contain "nvidia.com/gpu.present=true" to ensure that the DCGM pod is scheduled to these nodes.
        # resources: {}
  multicluster:
    clusterRole: none  # host | member | none  # You can install a solo cluster, or specify it as the Host or Member Cluster.
  network:
    networkpolicy: # Network policies allow network isolation within the same cluster, which means firewalls can be set up between certain instances (Pods).
      # Make sure that the CNI network plugin used by the cluster supports NetworkPolicy. There are a number of CNI network plugins that support NetworkPolicy, including Calico, Cilium, Kube-router, Romana and Weave Net.
      enabled: false # Enable or disable network policies.
    ippool: # Use Pod IP Pools to manage the Pod network address space. Pods to be created can be assigned IP addresses from a Pod IP Pool.
      type: none # Specify "calico" for this field if Calico is used as your CNI plugin. "none" means that Pod IP Pools are disabled.
    topology: # Use Service Topology to view Service-to-Service communication based on Weave Scope.
      type: none # Specify "weave-scope" for this field to enable Service Topology. "none" means that Service Topology is disabled.
  openpitrix: # An App Store that is accessible to all platform tenants. You can use it to manage apps across their entire lifecycle.
    store:
      enabled: false # Enable or disable the KubeSphere App Store.
  servicemesh:         # (0.3 Core, 300 MiB) Provide fine-grained traffic management, observability and tracing, and visualized traffic topology.
    enabled: false     # Base component (pilot). Enable or disable KubeSphere Service Mesh (Istio-based).
    istio:  # Customizing the istio installation configuration, refer to https://istio.io/latest/docs/setup/additional-setup/customize-installation/
      components:
        ingressGateways:
        - name: istio-ingressgateway
          enabled: false
        cni:
          enabled: false
  edgeruntime:          # Add edge nodes to your cluster and deploy workloads on edge nodes.
    enabled: false
    kubeedge:        # kubeedge configurations
      enabled: false
      cloudCore:
        cloudHub:
          advertiseAddress: # At least a public IP address or an IP address which can be accessed by edge nodes must be provided.
            - ""            # Note that once KubeEdge is enabled, CloudCore will malfunction if the address is not provided.
        service:
          cloudhubNodePort: "30000"
          cloudhubQuicNodePort: "30001"
          cloudhubHttpsNodePort: "30002"
          cloudstreamNodePort: "30003"
          tunnelNodePort: "30004"
        # resources: {}
        # hostNetWork: false
      iptables-manager:
        enabled: true 
        mode: "external"
        # resources: {}
      # edgeService:
      #   resources: {}
  gatekeeper:        # Provide admission policy and rule management, A validating (mutating TBA) webhook that enforces CRD-based policies executed by Open Policy Agent.
    enabled: false   # Enable or disable Gatekeeper.
    # controller_manager:
    #   resources: {}
    # audit:
    #   resources: {}
  terminal:
    # image: 'alpine:3.15' # There must be an nsenter program in the image
    timeout: 600         # Container timeout, if set to 0, no timeout will be used. The unit is seconds
            ''')
            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(cluster_config)

            # 读取 cluster-config.yaml 中的现有内容
            with open(file_path, 'r') as file:
                cluster_data = yaml.safe_load(file)

            # 合并 spec 部分
            if cluster_data and 'spec' in cluster_data:
                cluster_data['spec'].update(self.spec)

            # 将合并后的内容写入 cluster-config.yaml 文件
            with open(file_path, 'w') as file:
                yaml.dump(cluster_data, file)
                print("配置文件内容已合并到 cluster-config.yaml 文件")
                
            # 执行部署
            command = "kubectl apply -f ks-installer.yaml"
            self.base.com(command)
            command = "kubectl apply -f cluster-config.yaml"
            self.base.com(command)

            return True
        except Exception as e:
            print(f"配置默认 storageclass发生错误：{e}")
            self.logger.log(f"配置默认 storageclass发生错误：{e}")  # debug
            return False

    # 部署 LINSTOR CSI
    def configure_linstor_csi(self):
        controller_ip_value = None
        try:
            print("开始部署 LINSTOR CSI")
            controller_ip_value = f"http://{self.controller_ip}"
            # print(f"controller_ip_value: {controller_ip_value}")
            # print(f"self.controller_ip: {self.controller_ip}")
            # print(f"self.spec: {self.spec}")
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/linstor-csi.yaml"
            self.logger.log(f"在控制节点创建 linstor-csi.yaml 文件：{file_path}")
            braces = "{}"
            linstor_csi_config = textwrap.dedent(f'''
---
kind: StatefulSet
apiVersion: apps/v1
metadata:
  name: linstor-csi-controller
  namespace: kube-system
spec:
  serviceName: "linstor-csi"
  replicas: 1
  selector:
    matchLabels:
      app: linstor-csi-controller
      role: linstor-csi
  template:
    metadata:
      labels:
        app: linstor-csi-controller
        role: linstor-csi
    spec:
      priorityClassName: system-cluster-critical
      serviceAccount: linstor-csi-controller-sa
      containers:
        - name: csi-provisioner
          image: feixitek/csi-provisioner:v2.0.0
          args:
            - "--csi-address=$(ADDRESS)"
            - "--v=5"
            - "--feature-gates=Topology=true"
            - "--timeout=120s"
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          imagePullPolicy: "IfNotPresent"
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-attacher
          image: feixitek/csi-attacher:v3.0.0
          args:
            - "--v=5"
            - "--csi-address=$(ADDRESS)"
            - "--timeout=120s"
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          imagePullPolicy: "IfNotPresent"
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-resizer
          image: feixitek/csi-resizer:v1.0.0
          args:
          - "--v=5"
          - "--csi-address=$(ADDRESS)"
          env:
          - name: ADDRESS
            value: /var/lib/csi/sockets/pluginproxy/csi.sock
          imagePullPolicy: "IfNotPresent"
          volumeMounts:
          - mountPath: /var/lib/csi/sockets/pluginproxy/
            name: socket-dir
        - name: csi-snapshotter
          image: feixitek/csi-snapshotter:v3.0.0
          args:
            - "-csi-address=$(ADDRESS)"
            - "-timeout=120s"
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          imagePullPolicy: "IfNotPresent"  #sss
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: linstor-csi-plugin
          image: feixitek/linstor-csi-ppc64le:1.0.0
          args:
            - "--csi-endpoint=$(CSI_ENDPOINT)"
            - "--node=$(KUBE_NODE_NAME)"
            - "--linstor-endpoint=$(LINSTOR_IP)"
            - "--log-level=debug"
          env:
            - name: CSI_ENDPOINT
              value: unix:///var/lib/csi/sockets/pluginproxy/csi.sock
            - name: KUBE_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: LINSTOR_IP
              value: "{controller_ip_value}:3370"
          imagePullPolicy: "IfNotPresent"
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
      volumes:
        - name: socket-dir
          emptyDir: {braces}
---

kind: ServiceAccount
apiVersion: v1
metadata:
  name: linstor-csi-controller-sa
  namespace: kube-system

---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: linstor-csi-provisioner-role
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["list", "watch", "create", "update", "patch"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshots"]
    verbs: ["get", "list"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshotcontents"]
    verbs: ["get", "list"]

---

kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: linstor-csi-provisioner-binding
subjects:
  - kind: ServiceAccount
    name: linstor-csi-controller-sa
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: linstor-csi-provisioner-role
  apiGroup: rbac.authorization.k8s.io

---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: linstor-csi-attacher-role
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "update", "patch"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["csinodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments"]
    verbs: ["get", "list", "watch", "update", "patch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments/status"]
    verbs: ["get", "list", "watch", "update", "patch"]

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: linstor-csi-attacher-binding
subjects:
  - kind: ServiceAccount
    name: linstor-csi-controller-sa
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: linstor-csi-attacher-role
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: linstor-csi-resizer-role
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "patch"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims/status"]
    verbs: ["patch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["list", "watch", "create", "update", "patch"]

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: linstor-csi-resizer-binding
subjects:
  - kind: ServiceAccount
    name: linstor-csi-controller-sa
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: linstor-csi-resizer-role
  apiGroup: rbac.authorization.k8s.io

---

kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: linstor-csi-node
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: linstor-csi-node
      role: linstor-csi
  template:
    metadata:
      labels:
        app: linstor-csi-node
        role: linstor-csi
    spec:
      priorityClassName: system-node-critical
      serviceAccount: linstor-csi-node-sa
      containers:
        - name: csi-node-driver-registrar
          image: feixitek/csi-node-driver-registrar:v2.0.0
          args:
            - "--v=5"
            - "--csi-address=$(ADDRESS)"
            - "--kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)"
          lifecycle:
            preStop:
              exec:
                command: ["/bin/sh", "-c", "rm -rf /registration/linstor.csi.linbit.com /registration/linstor.csi.linbit.com-reg.sock"]
          env:
            - name: ADDRESS
              value: /csi/csi.sock
            - name: DRIVER_REG_SOCK_PATH
              value: /var/lib/kubelet/plugins/linstor.csi.linbit.com/csi.sock
            - name: KUBE_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          volumeMounts:
            - name: plugin-dir
              mountPath: /csi/
            - name: registration-dir
              mountPath: /registration/
        - name: linstor-csi-plugin
          image: feixitek/linstor-csi-ppc64le:1.0.0
          args:
            - "--csi-endpoint=$(CSI_ENDPOINT)"
            - "--node=$(KUBE_NODE_NAME)"
            - "--linstor-endpoint=$(LINSTOR_IP)"
            - "--log-level=debug"
          env:
            - name: CSI_ENDPOINT
              value: unix:///csi/csi.sock
            - name: KUBE_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: LINSTOR_IP
              value: "{controller_ip_value}:3370"
          imagePullPolicy: "IfNotPresent"
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN"]
            allowPrivilegeEscalation: true
          volumeMounts:
            - name: plugin-dir
              mountPath: /csi
            - name: pods-mount-dir
              mountPath: /var/lib/kubelet
              mountPropagation: "Bidirectional"
            - name: device-dir
              mountPath: /dev
      volumes:
        - name: registration-dir
          hostPath:
            path: /var/lib/kubelet/plugins_registry/
            type: DirectoryOrCreate
        - name: plugin-dir
          hostPath:
            path: /var/lib/kubelet/plugins/linstor.csi.linbit.com/
            type: DirectoryOrCreate
        - name: pods-mount-dir
          hostPath:
            path: /var/lib/kubelet
            type: Directory
        - name: device-dir
          hostPath:
            path: /dev
---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: linstor-csi-node-sa
  namespace: kube-system

---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: linstor-csi-driver-registrar-role
  namespace: kube-system
rules:
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]

---

apiVersion: storage.k8s.io/v1beta1
kind: CSIDriver
metadata:
  name: linstor.csi.linbit.com
spec:
  attachRequired: true
  podInfoOnMount: true

---

kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: linstor-csi-driver-registrar-binding
subjects:
  - kind: ServiceAccount
    name: linstor-csi-node-sa
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: linstor-csi-driver-registrar-role
  apiGroup: rbac.authorization.k8s.io

---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: linstor-csi-snapshotter-role
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["list", "watch", "create", "update", "patch"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshotclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshotcontents"]
    verbs: ["create", "get", "list", "watch", "update", "delete"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshotcontents/status"]
    verbs: ["update"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshots"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["apiextensions.k8s.io"]
    resources: ["customresourcedefinitions"]
    verbs: ["create", "list", "watch", "delete"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshots/status"]
    verbs: ["update"]

            ''')

            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(linstor_csi_config)

            # 执行部署
            command = "kubectl apply -f linstor-csi.yaml"
            self.base.com(command)

            return True
        except Exception as e:
            print(f"配置默认 storageclass发生错误：{e}")
            self.logger.log(f"配置默认 storageclass发生错误：{e}")  # debug
            return False
    
    # 创建 StorageClass
    def create_storageclass(self):
        try:
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/linstorsc.yaml"
            self.logger.log(f"在控制节点创建 linstorsc.yaml 文件：{file_path}")
            linstorsc_config = textwrap.dedent('''
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: linstor
provisioner: linstor.csi.linbit.com
parameters:
  autoPlace: "3"
  storagePool: "thpool1"
            ''')

            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(linstorsc_config)

            # 执行部署
            command = "kubectl apply -f linstorsc.yaml"
            self.base.com(command)

            return True
        except Exception as e:
            print(f"创建 StorageClass 发生错误：{e}")
            self.logger.log(f"创建 StorageClass 发生错误：{e}")  # debug
            return False
        
    # 创建 iSCSI 功能用到的 pvc
    def create_pvc_of_iscsi(self):
        try:
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/iscsipvc.yaml"
            self.logger.log(f"在控制节点创建 iscsipvc.yaml 文件：{file_path}")
            iscsipvc_config = textwrap.dedent('''
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: iscsi
  namespace: kubesphere-system
spec:
  storageClassName: linstor
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
            ''')

            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(iscsipvc_config)

            # 执行部署
            command = "kubectl apply -f iscsipvc.yaml"
            self.base.com(command)

            return True
        except Exception as e:
            print(f"创建 iSCSI 功能用到的 pvc 发生错误：{e}")
            self.logger.log(f"创建 iSCSI 功能用到的 pvc 发生错误：{e}")  # debug
            return False
        
    # 配置分布式存储节点
    # 配置 LINSTOR Controller ConfigMap
    def configure_linstor_controller_configMap(self):
        try:
            command = f"kubectl create configmap linstorip -n kubesphere-system --from-literal=user=admin --from-literal=linstorip={self.controller_ip}:3370"
            self.base.com(command)
            return True
        except Exception as e:
            print(f"配置 LINSTOR Controller ConfigMap时发生错误：{e}")
            self.logger.log(f"配置 LINSTOR Controller ConfigMap时发生错误:{e}")  # debug
            return False
        
    # 配置 ks-apiserver
    def configure_ks_apiserver(self):
        try:
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/ks-apiserver.yaml"
            self.logger.log(f"在控制节点创建 ks-apiserver.yaml 文件：{file_path}")
            ks_apiserver_config = textwrap.dedent('''
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    deployment.kubernetes.io/revision: "1"
    meta.helm.sh/release-name: ks-core
    meta.helm.sh/release-namespace: kubesphere-system
  labels:
    app: ks-apiserver
    app.kubernetes.io/managed-by: Helm
    tier: backend
    version: v3.1.0
    manager: kube-controller-manager
    operation: Update
  name: ks-apiserver
  namespace: kubesphere-system
  resourceVersion: "24251383"
  uid: 41cd18cd-3214-4bb6-b616-8cf45531ce1b
spec:
  progressDeadlineSeconds: 600
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: ks-apiserver
      tier: backend
  strategy:
    rollingUpdate:
      maxSurge: 0
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: ks-apiserver
        tier: backend
    spec:
      affinity:
        nodeAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - preference:
              matchExpressions:
              - key: node-role.kubernetes.io/master
                operator: In
                values:
                - ""
            weight: 100
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - ks-apiserver
            namespaces:
            - kubesphere-system
            topologyKey: kubernetes.io/hostname
      containers:
      - command:
        - ks-apiserver
        - --logtostderr=true
        image: feixitek/vtel-server:v1.1.0-ppc64
        imagePullPolicy: IfNotPresent
        livenessProbe:
          failureThreshold: 8
          httpGet:
            path: /kapis/version
            port: 9090
            scheme: HTTP
          initialDelaySeconds: 15
          periodSeconds: 10
          successThreshold: 1
          timeoutSeconds: 15
        name: ks-apiserver
        ports:
        - containerPort: 9090
          protocol: TCP
        resources:
          limits:
            cpu: "1"
            memory: 1Gi
          requests:
            cpu: 20m
            memory: 100Mi
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - name: iscsi
          mountPath: /etc/iscsi
        - name: localssh
          mountPath: /etc/localssh
        - mountPath: /etc/linstorip
          name: linstorip
        - mountPath: /etc/kubesphere/ingress-controller
          name: ks-router-config
        - mountPath: /etc/kubesphere/
          name: kubesphere-config
        - mountPath: /etc/localtime
          name: host-time
          readOnly: true
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      serviceAccount: kubesphere
      serviceAccountName: kubesphere
      terminationGracePeriodSeconds: 30
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
      - key: CriticalAddonsOnly
        operator: Exists
      - effect: NoExecute
        key: node.kubernetes.io/not-ready
        operator: Exists
        tolerationSeconds: 60
      - effect: NoExecute
        key: node.kubernetes.io/unreachable
        operator: Exists
        tolerationSeconds: 60
      volumes:
      - name: localssh
        hostPath:
          path: /root/.ssh
          type: ''
      - name: iscsi
        persistentVolumeClaim:
          claimName: iscsi
      - configMap:
          defaultMode: 420
          name: linstorip
        name: linstorip
      - configMap:
          defaultMode: 420
          name: ks-router-config
        name: ks-router-config
      - configMap:
          defaultMode: 420
          name: kubesphere-config
        name: kubesphere-config
      - hostPath:
          path: /etc/localtime
          type: ""
        name: host-time
            ''')
            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(ks_apiserver_config)

            print(f"检查 pod 是否创建完全，请稍等")
            self.logger.log(f"检查 pod 是否创建完全")
            if self.run_with_timeout():
                print("pod 创建完全，程序继续进行")
                # 执行部署
                command = "kubectl apply -f ks-apiserver.yaml"
                self.base.com(command)
                return True
            else:
                print("pod 创建超时")
                sys.exit()
                
        except Exception as e:
            print(f"配置 ks-apiserver发生错误：{e}")
            self.logger.log(f"配置 ks-apiserver发生错误：{e}")  # debug
            return False
        
    def run_with_timeout(self):
        start_time = time.time()
        max_duration = 180  # 最长运行时间（3分钟）
        interval = 10  # 每隔多久执行一次（10秒）

        while True:
            if time.time() - start_time > max_duration:
                # 达到最长运行时间，返回 False
                return False

            result = self.check_and_execute()  # 执行检查方法

            if result:
                # 如果返回 True，中断执行，返回 True
                return True

            time.sleep(interval)  # 等待指定的间隔时间
        
    def check_and_execute(self):
        try:
            pod_names = [
                'default-http-backend',
                'kubectl-admin',
                'alertmanager-main',
                'kube-state-metrics',
                'node-exporter',
                'notification-manager-operator',
                'prometheus-k8s',
                'prometheus-operator',
                'thanos-ruler',
                'ks-apiserver',
                'ks-console',
                'ks-controller-manager',
                'ks-installer',
            ]
            
            # 执行 kubectl get pod -A 命令并捕获输出
            result = self.base.com("kubectl get pod -A").stdout
            # 将输出按行分割
            lines = result.split('\n')
            buffer = 0
            # 遍历每一行输出
            for line in lines:
                # 检查每个要匹配的 Pod 名称是否在当前行中
                for name in pod_names:
                    if name in line:
                        buffer = buffer + 1
                        self.logger.log(f"pod 检查存在: {name}")
            
            if buffer == 13:
                return True
            else:
                return False
        except Exception as e:
            print(f"检查 pod 发生错误：{e}")
            self.logger.log(f"检查 pod 发生错误：{e}")  # debug
            return False
        
    def additiona_methods(self):
        try:
            # command = f"kubectl create namespace kubesphere-monitoring-system"
            # self.base.com(command)

            # command = f"kubectl get namespaces"
            # self.base.com(command)

            command = f"kubectl set image deployment.apps/notification-manager-operator notification-manager-operator=feixitek/notification-manager-operator-ppc64le:1.4.0 -n kubesphere-monitoring-system"
            self.base.com(command)

            # 创建 notifica_deploy.yaml 文件
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/notifica_deploy.yaml"
            self.logger.log(f"在控制节点创建 notifica_deploy.yaml 文件：{file_path}")
            notifica_deploy_config = textwrap.dedent('''
# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: notification.kubesphere.io/v2beta2
kind: NotificationManager
metadata:
  annotations:
    meta.helm.sh/release-name: notification-manager
    meta.helm.sh/release-namespace: kubesphere-monitoring-system
  creationTimestamp: "2023-12-14T02:42:50Z"
  generation: 1
  labels:
    app: notification-manager
    app.kubernetes.io/managed-by: Helm
  name: notification-manager
  resourceVersion: "3627"
  uid: d39915f0-ce76-43dc-9fea-d2143c152262
spec:
  affinity: {}
  defaultConfigSelector:
    matchLabels:
      type: default
  defaultSecretNamespace: kubesphere-monitoring-federated
  image: feixitek/notification-manager-ppc64le:1.4.0
  imagePullPolicy: IfNotPresent
  nodeSelector: {}
  portName: webhook
  receivers:
    globalReceiverSelector:
      matchLabels:
        type: global
    options:
      email:
        deliveryType: bulk
        notificationTimeout: 5
      global:
        templateFile:
        - /etc/notification-manager/template
      slack:
        notificationTimeout: 5
      wechat:
        notificationTimeout: 5
    tenantKey: user
    tenantReceiverSelector:
      matchLabels:
        type: tenant
  replicas: 1
  resources:
    limits:
      cpu: 500m
      memory: 500Mi
    requests:
      cpu: 5m
      memory: 20Mi
  serviceAccountName: notification-manager-sa
  tolerations: []
  volumeMounts:
  - mountPath: /etc/notification-manager/
    name: notification-manager-template
  volumes:
  - configMap:
      defaultMode: 420
      name: notification-manager-template
    name: notification-manager-template
            ''')                                                                                                 
            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(notifica_deploy_config)
            
            # 执行部署
            command = "kubectl delete -f notifica_deploy.yaml"
            self.base.com(command)
            command = "kubectl apply -f notifica_deploy.yaml"
            self.base.com(command)

            # 创建 thans.yaml 文件
            file_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/thans.yaml"
            self.logger.log(f"在控制节点创建 thans.yaml 文件：{file_path}")
            thans_config = textwrap.dedent('''
apiVersion: v1
items:
- apiVersion: monitoring.coreos.com/v1
  kind: ThanosRuler
  metadata:
    generation: 1
    labels:
      app.kubernetes.io/component: thanos-ruler
      app.kubernetes.io/instance: kubesphere
      app.kubernetes.io/name: thanos-ruler
      app.kubernetes.io/part-of: kube-prometheus
      app.kubernetes.io/version: 0.25.2
    managedFields:
    - apiVersion: monitoring.coreos.com/v1
      fieldsType: FieldsV1
      fieldsV1:
        f:metadata:
          f:annotations:
            .: {}
            f:kubectl.kubernetes.io/last-applied-configuration: {}
          f:labels:
            .: {}
            f:app.kubernetes.io/component: {}
            f:app.kubernetes.io/instance: {}
            f:app.kubernetes.io/name: {}
            f:app.kubernetes.io/part-of: {}
            f:app.kubernetes.io/version: {}
        f:spec:
          .: {}
          f:affinity:
            .: {}
            f:podAntiAffinity:
              .: {}
              f:preferredDuringSchedulingIgnoredDuringExecution: {}
          f:alertmanagersUrl: {}
          f:image: {}
          f:nodeSelector:
            .: {}
            f:kubernetes.io/os: {}
          f:podMetadata:
            .: {}
            f:labels:
              .: {}
              f:app.kubernetes.io/component: {}
              f:app.kubernetes.io/instance: {}
              f:app.kubernetes.io/name: {}
              f:app.kubernetes.io/part-of: {}
              f:app.kubernetes.io/version: {}
          f:queryEndpoints: {}
          f:replicas: {}
          f:resources:
            .: {}
            f:limits:
              .: {}
              f:cpu: {}
              f:memory: {}
            f:requests:
              .: {}
              f:cpu: {}
              f:memory: {}
          f:ruleNamespaceSelector: {}
          f:ruleSelector:
            .: {}
            f:matchLabels:
              .: {}
              f:role: {}
              f:thanos-ruler: {}
          f:tolerations: {}
      manager: kubectl-client-side-apply
      operation: Update
      time: "2023-12-14T02:43:02Z"
    name: kubesphere
    namespace: kubesphere-monitoring-system
    resourceVersion: "3694"
    uid: bcb47d03-3071-4ae3-a1ae-b801e547fd9d
  spec:
    affinity:
      podAntiAffinity:
        preferredDuringSchedulingIgnoredDuringExecution:
        - podAffinityTerm:
            labelSelector:
              matchLabels:
                app.kubernetes.io/component: thanos-ruler
                app.kubernetes.io/instance: kubesphere
                app.kubernetes.io/name: thanos-ruler
                app.kubernetes.io/part-of: kube-prometheus
            namespaces:
            - kubesphere-monitoring-system
            topologyKey: kubernetes.io/hostname
          weight: 100
    alertmanagersUrl:
    - dnssrv+http://alertmanager-operated.kubesphere-monitoring-system.svc:9093
    image: thanosio/thanos-linux-ppc64le:v0.26.0
    nodeSelector:
      kubernetes.io/os: linux
    podMetadata:
      labels:
        app.kubernetes.io/component: thanos-ruler
        app.kubernetes.io/instance: kubesphere
        app.kubernetes.io/name: thanos-ruler
        app.kubernetes.io/part-of: kube-prometheus
        app.kubernetes.io/version: 0.25.2
    queryEndpoints:
    - http://prometheus-operated.kubesphere-monitoring-system.svc:9090
    replicas: 1
    resources:
      limits:
        cpu: "1"
        memory: 1Gi
      requests:
        cpu: 100m
        memory: 100Mi
    ruleNamespaceSelector: {}
    ruleSelector:
      matchLabels:
        role: alert-rules
        thanos-ruler: kubesphere
    tolerations: []
kind: List
metadata:
  resourceVersion: ""
  selfLink: ""
            ''')
            # 打开文件并读取内容
            with open(file_path, 'w') as file:
                file.write(thans_config)
            
            # 执行部署
            command = "kubectl delete -f thans.yaml"
            self.base.com(command)
            command = "kubectl apply -f thans.yaml"
            self.base.com(command)

            # 执行以下命令
            command = "kubectl set resources statefulset.apps/prometheus-k8s -c=prometheus --limits=memory=8Gi,cpu=8 --requests=memory=8Gi,cpu=8 -n kubesphere-monitoring-system"
            self.base.com(command)
            command = "kubectl set resources statefulset.apps/prometheus-k8s -c=config-reloader --limits=memory=200Mi,cpu=100m --requests=memory=200Mi,cpu=100m -n kubesphere-monitoring-system"
            self.base.com(command)
            command = "kubectl set resources deployment.apps/default-http-backend -c=default-http-backend --limits=memory=100Mi,cpu=10m --requests=memory=100Mi,cpu=10m -n kubesphere-controls-system"
            self.base.com(command)
            command = "kubectl set resources deployment.apps/coredns -c=coredns --limits=memory=270Mi --requests=memory=200Mi,cpu=100m -n kube-system"
            self.base.com(command)
            command = "kubectl set resources deployment.apps/notification-manager-operator -c=kube-rbac-proxy --limits=memory=2Gi,cpu=400m --requests=memory=1Gi,cpu=400m -n kubesphere-monitoring-system"
            self.base.com(command)
            command = "kubectl set resources deployment.apps/notification-manager-operator -c=notification-manager-operator --limits=memory=100Mi,cpu=50m --requests=memory=100Mi,cpu=50m -n kubesphere-monitoring-system"
            self.base.com(command)
            command = "kubectl set resources deployment.apps/notification-manager-deployment -c=notification-manager --limits=memory=500Mi,cpu=500m --requests=memory=200Mi,cpu=50m -n kubesphere-monitoring-system"
            self.base.com(command)
            command = "kubectl set resources statefulset.apps/alertmanager-main -c=alertmanager --limits=memory=800Mi,cpu=200m --requests=memory=800Mi,cpu=100m -n kubesphere-monitoring-system"
            self.base.com(command)
            command = "kubectl set resources statefulset.apps/alertmanager-main -c=config-reloader --limits=memory=200Mi,cpu=100m --requests=memory=200Mi,cpu=100m -n kubesphere-monitoring-system"
            self.base.com(command)
            command = "kubectl set resources deployment.apps/prometheus-operator -c=prometheus-operator --limits=memory=500Mi,cpu=200m --requests=memory=300Mi,cpu=100m -n kubesphere-monitoring-system"
            self.base.com(command)

            return True
        except Exception as e:
            print(f"执行追加方法发生错误：{e}")
            self.logger.log(f"执行追加方法发生错误：{e}")  # debug
            return False
