#! /usr/bin/env python3

import argparse
import sys
from log_record import Logger
from csmdeployer import Csmdeployer, Exchange

# kubernetes 集群预配置
def kubernetes(csm):
    if csm.initialising_kubernetes_cluster():
        print("初始化 Kubernetes 集群完成\n")
    if csm.configure_kubectl_tool():
        print("配置 kubectl 工具完成")
    if csm.configure_net():
        print("配置网络完成")
    if csm.configure_controller():
        print("配置 controller 节点完成")
    if csm.configure_storageclass():
        print("配置默认 storageclass 完成")
    print("\n",end="")

# 初始化 CoSAN Manager
def initialising_cosan_manager(csm):
    if csm.initialising_cosan_manager():
        print("初始化 CoSAN Manager 完成")
    print("\n",end="")    

# 更改 image
def exchange_image(exc):
    if exc.update_images_from_config():
        print("更新 image 方法执行完成")
    print("\n",end="")

# 部署 LINSTOR CSI
def deploy_linstaor_csi(csm):
    if csm.configure_linstor_csi():
        print("部署 LINSTOR CSI 完成")
    if csm.create_storageclass():
        print("创建 StorageClass 完成")
    if csm.create_pvc_of_iscsi():
        print("创建 iSCSI 功能用到的 pvc 完成")
    print("\n",end="")

# 配置分布式存储节点
def configure_distributed_storage_nodes(csm):
    if csm.configure_linstor_controller_configMap():
        print("配置 LINSTOR Controller ConfigMap 完成")
    if csm.configure_ks_apiserver():
        print("配置 ks-apiserver 完成")
    print("\n",end="")

# 执行追加方法
def execute_additiona_methods(csm):
    if csm.additiona_methods():
        print("\n",end="")

def display_version():
    print("version: v1.0.0")

def main():
    parser = argparse.ArgumentParser(description='csmdeployer')
    parser.add_argument('-i', '--initialise', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('-k', '--kubernetes', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('-c', '--configure', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('-e', '--exchange', action='store_true',
                        help='exchange image')
    parser.add_argument('-d', '--deploy', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('-v', '--version', action='store_true',
                        help='show version information')
    args = parser.parse_args()

    if args.version:
        display_version()
        sys.exit()

    logger = Logger("csmdeployer")
    csm = Csmdeployer(logger)
    exc = Exchange(logger)
    
    if args.exchange: 
        exchange_image(exc) 
    else:
        print("开始进行部署\n")
        kubernetes(csm)
        initialising_cosan_manager(csm)
        deploy_linstaor_csi(csm)
        configure_distributed_storage_nodes(csm)
        execute_additiona_methods(csm)
        print("部署完成")

if __name__ == '__main__':
    main()